import base64
import json
import os
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / "lambda"))

import lambda_function


def encode(value):
    if not isinstance(value, bytes):
        value = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def token(claims):
    return f"{encode({'alg': 'RS256', 'kid': 'key-1'})}.{encode(claims)}.{encode(b'signature')}"


def valid_claims():
    now = int(time.time())
    return {
        "aud": "takoyaki3-auth",
        "iss": "https://securetoken.google.com/takoyaki3-auth",
        "sub": "firebase-user-1",
        "email": "owner@example.com",
        "email_verified": True,
        "iat": now - 10,
        "exp": now + 3600,
        "auth_time": now - 20,
    }


class FirebaseJwtTests(unittest.TestCase):
    @patch.dict(os.environ, {"FIREBASE_PROJECT_ID": "takoyaki3-auth"})
    @patch("lambda_function._verify_rs256")
    @patch("lambda_function._load_firebase_keys", return_value={"key-1": {}})
    def test_valid_claims_are_verified(self, _keys, verify_signature):
        claims = valid_claims()

        self.assertEqual(lambda_function._verify_firebase_jwt(token(claims)), claims)
        verify_signature.assert_called_once()

    @patch.dict(os.environ, {"FIREBASE_PROJECT_ID": "takoyaki3-auth"})
    @patch("lambda_function._verify_rs256")
    @patch("lambda_function._load_firebase_keys", return_value={"key-1": {}})
    def test_expired_token_is_rejected(self, _keys, _verify_signature):
        claims = valid_claims()
        claims["exp"] = int(time.time()) - 1

        with self.assertRaisesRegex(lambda_function.JwtVerificationError, "有効期限"):
            lambda_function._verify_firebase_jwt(token(claims))

    @patch("lambda_function._verify_firebase_jwt", return_value=valid_claims())
    def test_authorizer_returns_policy_for_all_stage_routes(self, _verify):
        result = lambda_function.authorizer({
            "authorizationToken": "Bearer token",
            "methodArn": "arn:aws:execute-api:ap-northeast-1:123456789012:api123/prod/GET/status",
        }, None)

        self.assertEqual(result["principalId"], "firebase-user-1")
        self.assertEqual(
            result["policyDocument"]["Statement"][0]["Resource"],
            "arn:aws:execute-api:ap-northeast-1:123456789012:api123/prod/*/*",
        )
        self.assertEqual(result["context"]["email"], "owner@example.com")

    def test_lambda_response_allows_all_origins(self):
        response = lambda_function._response(200, {"ok": True})

        self.assertEqual(response["headers"]["access-control-allow-origin"], "*")

    @patch.dict(os.environ, {
        "ALLOWED_EMAILS": "owner@example.com",
        "SWITCHBOT_TOKEN": "token",
        "SWITCHBOT_SECRET": "secret",
        "SWITCHBOT_DEVICE_ID": "lock-1",
    })
    @patch("lambda_function.SwitchBotClient")
    def test_rest_api_unlock_route_uses_authorizer_context(self, client_class):
        response = lambda_function.handler({
            "httpMethod": "POST",
            "resource": "/unlock",
            "requestContext": {"authorizer": {
                "sub": "firebase-user-1",
                "email": "owner@example.com",
                "email_verified": "true",
            }},
        }, None)

        self.assertEqual(response["statusCode"], 200)
        client_class.return_value.set_locked.assert_called_once_with(False)


if __name__ == "__main__":
    unittest.main()
