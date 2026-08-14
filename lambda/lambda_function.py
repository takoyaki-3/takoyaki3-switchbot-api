"""認証済みユーザーからSwitchBotロックを操作するLambdaハンドラー。"""

from __future__ import annotations

import html
import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


API_BASE_URL = "https://api.switch-bot.com/v1.1"
SUCCESS_CODE = 100
FIREBASE_JWKS_URL = (
    "https://www.googleapis.com/service_accounts/v1/jwk/"
    "securetoken@system.gserviceaccount.com"
)
SHA256_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
_jwks_cache: tuple[float, dict[str, Any]] | None = None


class SwitchBotError(RuntimeError):
    """SwitchBot API の呼び出しに失敗した場合の例外。"""


class JwtVerificationError(RuntimeError):
    """Firebase JWTの検証に失敗した場合の例外。"""


@dataclass(frozen=True)
class Config:
    token: str
    secret: str
    device_id: str


class SwitchBotClient:
    """SwitchBot OpenAPI v1.1 のスマートロッククライアント。"""

    def __init__(self, config: Config, *, timeout: float = 10.0) -> None:
        self.config = config
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        timestamp = str(int(time.time() * 1000))
        nonce = str(uuid.uuid4())
        message = f"{self.config.token}{timestamp}{nonce}".encode("utf-8")
        signature = base64.b64encode(
            hmac.new(
                self.config.secret.encode("utf-8"),
                message,
                hashlib.sha256,
            ).digest()
        ).decode("ascii")
        return {
            "Authorization": self.config.token,
            "Content-Type": "application/json; charset=utf-8",
            "t": timestamp,
            "sign": signature,
            "nonce": nonce,
        }

    def _request(
        self, method: str, path: str, payload: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(
            f"{API_BASE_URL}{path}",
            data=data,
            headers=self._headers(),
            method=method,
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                result = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise SwitchBotError(f"HTTP {exc.code}: {detail}") from exc
        except URLError as exc:
            raise SwitchBotError(f"SwitchBot API に接続できません: {exc.reason}") from exc
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SwitchBotError("SwitchBot API から不正な応答を受信しました") from exc

        if result.get("statusCode") != SUCCESS_CODE:
            raise SwitchBotError(
                f"APIエラー {result.get('statusCode', 'unknown')}: "
                f"{result.get('message', '詳細なし')}"
            )
        return result

    def status(self) -> dict[str, Any]:
        result = self._request("GET", f"/devices/{self.config.device_id}/status")
        return result.get("body", {})

    def set_locked(self, locked: bool) -> None:
        self._request(
            "POST",
            f"/devices/{self.config.device_id}/commands",
            {
                "command": "lock" if locked else "unlock",
                "parameter": "default",
                "commandType": "command",
            },
        )


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def _response(status: int, body: Any, content_type: str = "application/json") -> dict[str, Any]:
    """API Gateway REST API形式のレスポンスへ共通ヘッダーを付与する。"""
    if content_type == "application/json":
        body = json.dumps(body, ensure_ascii=False)
    return {
        "statusCode": status,
        "headers": {
            "content-type": f"{content_type}; charset=utf-8",
            "access-control-allow-origin": "*",
            "cache-control": "no-store",
            "x-content-type-options": "nosniff",
            "content-security-policy": (
                "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
            ),
            "referrer-policy": "no-referrer",
        },
        "body": body,
    }


def _base64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise JwtVerificationError("JWTのBase64URL形式が不正です") from exc


def _load_firebase_keys(*, force_refresh: bool = False) -> dict[str, Any]:
    """Firebase公開鍵を取得し、Cache-Controlの有効期間内は再利用する。"""
    global _jwks_cache
    now = time.time()
    if not force_refresh and _jwks_cache is not None and _jwks_cache[0] > now:
        return _jwks_cache[1]

    request = Request(FIREBASE_JWKS_URL, headers={"Accept": "application/json"})
    try:
        with urlopen(request, timeout=5) as response:
            document = json.loads(response.read().decode("utf-8"))
            cache_control = response.headers.get("Cache-Control", "")
    except (HTTPError, URLError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise JwtVerificationError("Firebase公開鍵を取得できません") from exc

    keys = {
        key["kid"]: key
        for key in document.get("keys", [])
        if isinstance(key, dict)
        and key.get("kid")
        and key.get("kty") == "RSA"
        and key.get("alg") == "RS256"
        and key.get("use") == "sig"
    }
    if not keys:
        raise JwtVerificationError("Firebase公開鍵が空です")

    max_age = 3600
    for directive in cache_control.split(","):
        name, separator, value = directive.strip().partition("=")
        if separator and name.lower() == "max-age" and value.isdigit():
            max_age = min(int(value), 7200)
            break
    _jwks_cache = (now + max_age, keys)
    return keys


def _verify_rs256(signing_input: bytes, signature: bytes, jwk: dict[str, Any]) -> None:
    """RSA PKCS#1 v1.5 + SHA-256署名をJWK公開鍵で検証する。"""
    try:
        modulus = int.from_bytes(_base64url_decode(jwk["n"]), "big")
        exponent = int.from_bytes(_base64url_decode(jwk["e"]), "big")
    except (KeyError, TypeError) as exc:
        raise JwtVerificationError("Firebase公開鍵の形式が不正です") from exc

    key_size = (modulus.bit_length() + 7) // 8
    if len(signature) != key_size:
        raise JwtVerificationError("JWT署名の長さが不正です")
    encoded = pow(int.from_bytes(signature, "big"), exponent, modulus).to_bytes(
        key_size, "big"
    )
    digest_info = SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(signing_input).digest()
    padding_length = key_size - len(digest_info) - 3
    if padding_length < 8:
        raise JwtVerificationError("Firebase公開鍵の長さが不正です")
    expected = b"\x00\x01" + (b"\xff" * padding_length) + b"\x00" + digest_info
    if not hmac.compare_digest(encoded, expected):
        raise JwtVerificationError("JWT署名が一致しません")


def _verify_firebase_jwt(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise JwtVerificationError("JWTの形式が不正です")
    try:
        header = json.loads(_base64url_decode(parts[0]).decode("utf-8"))
        claims = json.loads(_base64url_decode(parts[1]).decode("utf-8"))
        signature = _base64url_decode(parts[2])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise JwtVerificationError("JWTを解析できません") from exc
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise JwtVerificationError("JWTのheaderまたはpayloadが不正です")
    if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
        raise JwtVerificationError("JWTの署名方式が不正です")

    keys = _load_firebase_keys()
    key = keys.get(header["kid"])
    if key is None:
        key = _load_firebase_keys(force_refresh=True).get(header["kid"])
    if key is None:
        raise JwtVerificationError("JWTのkidに対応する公開鍵がありません")
    _verify_rs256(f"{parts[0]}.{parts[1]}".encode("ascii"), signature, key)

    project_id = os.environ["FIREBASE_PROJECT_ID"]
    now = int(time.time())
    audience = claims.get("aud")
    audience_matches = audience == project_id or (
        isinstance(audience, list) and project_id in audience
    )
    if not audience_matches:
        raise JwtVerificationError("JWTのaudienceが一致しません")
    if claims.get("iss") != f"https://securetoken.google.com/{project_id}":
        raise JwtVerificationError("JWTのissuerが一致しません")
    if not isinstance(claims.get("exp"), (int, float)) or claims["exp"] <= now:
        raise JwtVerificationError("JWTの有効期限が切れています")
    if not isinstance(claims.get("iat"), (int, float)) or claims["iat"] > now + 30:
        raise JwtVerificationError("JWTの発行時刻が不正です")
    if isinstance(claims.get("nbf"), (int, float)) and claims["nbf"] > now + 30:
        raise JwtVerificationError("JWTはまだ有効ではありません")
    if not isinstance(claims.get("auth_time"), (int, float)) or claims["auth_time"] > now + 30:
        raise JwtVerificationError("JWTの認証時刻が不正です")
    subject = claims.get("sub")
    if not isinstance(subject, str) or not 1 <= len(subject) <= 128:
        raise JwtVerificationError("JWTのsubjectが不正です")
    return claims


def _authorizer_resource(method_arn: str) -> str:
    """キャッシュした認証結果を全操作ルートで使えるREST API ARNへ変換する。"""
    parts = method_arn.split("/")
    if len(parts) < 3:
        raise JwtVerificationError("methodArnの形式が不正です")
    return "/".join([parts[0], parts[1], "*", "*"])


def authorizer(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    """REST API TOKEN AuthorizerとしてFirebase IDトークンを検証する。"""
    try:
        token = str(event.get("authorizationToken", "")).strip()
        if token.lower().startswith("bearer "):
            token = token[7:].strip()
        if not token:
            raise JwtVerificationError("Authorizationヘッダーがありません")
        claims = _verify_firebase_jwt(token)
        resource = _authorizer_resource(str(event.get("methodArn", "")))
    except (JwtVerificationError, KeyError, TypeError, ValueError) as exc:
        logger.warning("Firebase JWT verification failed: %s", exc)
        raise Exception("Unauthorized") from None

    return {
        "principalId": claims["sub"],
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [{
                "Action": "execute-api:Invoke",
                "Effect": "Allow",
                "Resource": resource,
            }],
        },
        "context": {
            "sub": claims["sub"],
            "email": str(claims.get("email", "")),
            "email_verified": bool(claims.get("email_verified", False)),
        },
    }


def _config() -> Config:
    """GitHub Actionsから設定されたLambda環境変数を読み込む。"""
    return Config(
        token=os.environ["SWITCHBOT_TOKEN"],
        secret=os.environ["SWITCHBOT_SECRET"],
        device_id=os.environ["SWITCHBOT_DEVICE_ID"],
    )


def _claims(event: dict[str, Any]) -> dict[str, Any]:
    """API Gatewayが検証済みのJWT claimをイベントから取り出す。"""
    context = event.get("requestContext", {}).get("authorizer", {})
    return context.get("jwt", {}).get("claims", {}) if "jwt" in context else context


def _authorized(event: dict[str, Any]) -> tuple[bool, str]:
    """検証済みclaimをアプリ固有の許可メールリストと照合する。"""
    claims = _claims(event)
    email = str(claims.get("email", "")).strip().lower()
    subject = str(claims.get("sub", "")).strip()
    verified = claims.get("email_verified") in (True, "true", "True", "1")
    allowed = {x.strip().lower() for x in os.environ.get("ALLOWED_EMAILS", "").split(",") if x.strip()}
    return bool(subject and email and verified and email in allowed), email


def _login_redirect(event: dict[str, Any]) -> dict[str, Any]:
    # API GatewayのHostではなく、利用者から見えるリバースプロキシのURLへ戻す。
    callback = f"{os.environ['PUBLIC_BASE_URL'].rstrip('/')}/control"
    login_url = os.environ["AUTH_LOGIN_URL"].rstrip("/")
    return {"statusCode": 302, "headers": {
        "location": f"{login_url}?r={quote(callback, safe='')}",
        "cache-control": "no-store",
        "access-control-allow-origin": "*",
    }, "body": ""}


def _control_page() -> dict[str, Any]:
    """JWTをBearerヘッダーで操作APIへ送る最小限のブラウザ画面を返す。"""
    login_url = html.escape(os.environ["AUTH_LOGIN_URL"].rstrip("/"), quote=True)
    page = f"""<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Takoyaki3 Lock</title><style>
body{{font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;background:#f6f7f9;color:#18202a}}
main{{background:white;padding:2rem;border-radius:1rem;box-shadow:0 4px 24px #0001}}
button{{font:inherit;padding:.8rem 1.3rem;margin:.4rem;border:0;border-radius:.6rem;cursor:pointer}}
.unlock{{background:#c62828;color:white}} .lock{{background:#263238;color:white}} #message{{min-height:1.5rem}}
</style></head><body><main><h1>玄関ロック</h1><p id="message">認証を確認しています…</p>
<button class="lock" data-action="lock" disabled>施錠</button>
<button class="unlock" data-action="unlock" disabled>解錠</button></main><script>
const loginUrl = '{login_url}';
const params = new URLSearchParams(location.search);
if (params.has('jwt')) {{ sessionStorage.setItem('authIdToken', params.get('jwt')); history.replaceState(null, '', location.pathname); }}
const token = sessionStorage.getItem('authIdToken');
const apiBase = location.pathname.endsWith('/control') ? location.pathname.slice(0, -8) : '';
const message = document.querySelector('#message');
const buttons = [...document.querySelectorAll('button')];
function login() {{ location.replace(loginUrl + '?r=' + encodeURIComponent(location.origin + location.pathname)); }}
async function call(path, options={{}}) {{
  if (!token) return login();
  const response = await fetch(apiBase + path, {{...options, headers: {{Authorization: 'Bearer ' + token}}}});
  if (response.status === 401 || response.status === 403) {{ sessionStorage.removeItem('authIdToken'); return login(); }}
  const data = await response.json();
  if (!response.ok) throw new Error(data.message || 'APIエラー');
  return data;
}}
async function refresh() {{
  try {{ const data = await call('/status'); message.textContent = '状態: ' + (data.lockState || data.status || '不明'); buttons.forEach(b => b.disabled=false); }}
  catch (e) {{ message.textContent = e.message; }}
}}
buttons.forEach(button => button.addEventListener('click', async () => {{
  const action = button.dataset.action;
  if (action === 'unlock' && !confirm('本当に解錠しますか？')) return;
  buttons.forEach(b => b.disabled=true); message.textContent = '送信中…';
  try {{ await call('/' + action, {{method:'POST'}}); message.textContent = action === 'lock' ? '施錠しました' : '解錠しました'; }}
  catch (e) {{ message.textContent = e.message; }} finally {{ buttons.forEach(b => b.disabled=false); }}
}}));
refresh();
</script></body></html>"""
    return _response(200, page, "text/html")


def handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    """API Gateway REST APIのメソッドとリソースに応じて処理する。"""
    route = f"{event.get('httpMethod', '')} {event.get('resource', event.get('path', ''))}"
    if route == "GET /":
        return _login_redirect(event)
    if route == "GET /control":
        return _control_page()

    # ここへ到達する操作系ルートは、JWT検証に加えてアプリ側の認可も必須とする。
    authorized, email = _authorized(event)
    if not authorized:
        return _response(403, {"message": "このユーザーには操作権限がありません"})
    try:
        client = SwitchBotClient(_config())
        if route == "GET /status":
            return _response(200, {**client.status(), "user": email})
        if route == "POST /lock":
            client.set_locked(True)
            logger.info("Lock action completed for %s", email)
            return _response(200, {"ok": True, "action": "lock"})
        if route == "POST /unlock":
            client.set_locked(False)
            logger.info("Unlock action completed for %s", email)
            return _response(200, {"ok": True, "action": "unlock"})
        return _response(404, {"message": "Not found"})
    except (SwitchBotError, KeyError, ValueError, json.JSONDecodeError):
        # 上流APIの応答やシークレット内容は利用者へ返さず、CloudWatch Logsだけに記録する。
        logger.exception("SwitchBot operation failed for %s", email)
        return _response(502, {"message": "SwitchBotの操作に失敗しました"})
