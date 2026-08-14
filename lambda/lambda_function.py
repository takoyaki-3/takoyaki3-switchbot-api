"""認証済みユーザーからSwitchBotロックを操作するLambdaハンドラー。"""

from __future__ import annotations

import html
import base64
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


class SwitchBotError(RuntimeError):
    """SwitchBot API の呼び出しに失敗した場合の例外。"""


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
    """API Gateway HTTP API形式のレスポンスへ共通セキュリティヘッダーを付与する。"""
    if content_type == "application/json":
        body = json.dumps(body, ensure_ascii=False)
    return {
        "statusCode": status,
        "headers": {
            "content-type": f"{content_type}; charset=utf-8",
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


def _config() -> Config:
    """GitHub Actionsから設定されたLambda環境変数を読み込む。"""
    return Config(
        token=os.environ["SWITCHBOT_TOKEN"],
        secret=os.environ["SWITCHBOT_SECRET"],
        device_id=os.environ["SWITCHBOT_DEVICE_ID"],
    )


def _claims(event: dict[str, Any]) -> dict[str, Any]:
    """API Gatewayが検証済みのJWT claimをイベントから取り出す。"""
    return event.get("requestContext", {}).get("authorizer", {}).get("jwt", {}).get("claims", {})


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
        "location": f"{login_url}?r={quote(callback, safe='')}", "cache-control": "no-store"
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
const message = document.querySelector('#message');
const buttons = [...document.querySelectorAll('button')];
function login() {{ location.replace(loginUrl + '?r=' + encodeURIComponent(location.origin + '/control')); }}
async function call(path, options={{}}) {{
  if (!token) return login();
  const response = await fetch(path, {{...options, headers: {{Authorization: 'Bearer ' + token}}}});
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
    """API GatewayのrouteKeyに応じて画面配信またはロック操作を実行する。"""
    route = event.get("routeKey", "")
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
