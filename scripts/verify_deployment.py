"""AWS CLIでデプロイ情報を取得し、JWT認証付きでAPIを確認する。"""

from __future__ import annotations

import argparse
import getpass
import json
import subprocess
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


DEFAULT_STACK_NAME = "Takoyaki3LockStack"
DEFAULT_REGION = "ap-northeast-1"


class VerificationError(RuntimeError):
    """デプロイ確認を継続できない場合の例外。"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CloudFormationスタックを取得し、JWTでGET /statusを呼び出します。"
    )
    parser.add_argument("--stack-name", default=DEFAULT_STACK_NAME)
    parser.add_argument("--region", default=DEFAULT_REGION)
    parser.add_argument(
        "--profile",
        help="AWS CLIで利用するプロファイル名。省略時は現在の認証情報を使います。",
    )
    return parser.parse_args()


def describe_stack(stack_name: str, region: str, profile: str | None) -> dict[str, Any]:
    command = [
        "aws",
        "cloudformation",
        "describe-stacks",
        "--stack-name",
        stack_name,
        "--region",
        region,
        "--output",
        "json",
        "--no-cli-pager",
    ]
    if profile:
        command.extend(["--profile", profile])

    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
    except FileNotFoundError as exc:
        raise VerificationError(
            "AWS CLIが見つかりません。awsコマンドをインストールしてください。"
        ) from exc

    if result.returncode != 0:
        detail = result.stderr.strip() or "詳細なし"
        raise VerificationError(f"スタック情報を取得できませんでした: {detail}")

    try:
        stacks = json.loads(result.stdout).get("Stacks", [])
    except json.JSONDecodeError as exc:
        raise VerificationError("awsコマンドのJSON応答を解析できませんでした。") from exc
    if len(stacks) != 1:
        raise VerificationError(f"スタック {stack_name!r} が見つかりません。")
    return stacks[0]


def stack_outputs(stack: dict[str, Any]) -> dict[str, str]:
    return {
        output["OutputKey"]: output["OutputValue"]
        for output in stack.get("Outputs", [])
        if "OutputKey" in output and "OutputValue" in output
    }


def read_jwt() -> str:
    token = getpass.getpass("Firebase JWTを貼り付けてEnterを押してください: ").strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    if not token:
        raise VerificationError("JWTが入力されていません。")
    return token


def request_status(api_url: str, token: str) -> tuple[int, Any]:
    request = Request(
        f"{api_url.rstrip('/')}/status",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        },
        method="GET",
    )
    try:
        with urlopen(request, timeout=20) as response:
            status = response.status
            body = response.read().decode("utf-8")
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise VerificationError(f"APIがHTTP {exc.code}を返しました: {body}") from exc
    except URLError as exc:
        raise VerificationError(f"APIへ接続できませんでした: {exc.reason}") from exc

    try:
        return status, json.loads(body)
    except json.JSONDecodeError:
        return status, body


def main() -> int:
    args = parse_args()
    try:
        stack = describe_stack(args.stack_name, args.region, args.profile)
        outputs = stack_outputs(stack)
        api_url = outputs.get("ApiUrl")
        if not api_url:
            raise VerificationError("スタック出力にApiUrlがありません。")

        print(f"Stack: {stack.get('StackName', args.stack_name)}")
        print(f"Status: {stack.get('StackStatus', 'unknown')}")
        print(f"API URL: {api_url}")
        if public_url := outputs.get("PublicUrl"):
            print(f"Public URL: {public_url}")

        token = read_jwt()
        status, body = request_status(api_url, token)
        print(f"API response: HTTP {status}")
        if isinstance(body, (dict, list)):
            print(json.dumps(body, ensure_ascii=False, indent=2))
        else:
            print(body)
        return 0
    except VerificationError as exc:
        print(f"エラー: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
