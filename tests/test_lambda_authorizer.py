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
    })
    @patch("lambda_function._get_configured_device", return_value={
        "device_name": "lock", "device_id": "lock-1", "kind": "lock",
    })
    @patch("lambda_function.SwitchBotClient")
    def test_rest_api_unlock_route_uses_authorizer_context(self, client_class, _device):
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
        client_class.return_value.command.assert_called_once_with("lock-1", "unlock")

    @patch.dict(os.environ, {
        "ALLOWED_EMAILS": "owner@example.com",
        "SWITCHBOT_TOKEN": "token",
        "SWITCHBOT_SECRET": "secret",
    })
    @patch("lambda_function._get_configured_device", return_value={
        "device_name": "light", "device_id": "light-1", "kind": "power",
    })
    @patch("lambda_function.SwitchBotClient")
    def test_light_on_maps_to_switchbot_turn_on(self, client_class, _device):
        response = lambda_function.handler({
            "httpMethod": "POST",
            "resource": "/devices/{device}/actions",
            "pathParameters": {"device": "light"},
            "body": json.dumps({"action": "on"}),
            "requestContext": {"authorizer": {
                "sub": "firebase-user-1",
                "email": "owner@example.com",
                "email_verified": "true",
            }},
        }, None)

        self.assertEqual(response["statusCode"], 200)
        client_class.return_value.command.assert_called_once_with("light-1", "turnOn")

    @patch.dict(os.environ, {
        "ALLOWED_EMAILS": "owner@example.com",
        "SWITCHBOT_TOKEN": "token",
        "SWITCHBOT_SECRET": "secret",
    })
    @patch("lambda_function._get_configured_device", return_value={
        "device_name": "fan", "device_id": "fan-1", "kind": "power",
    })
    @patch("lambda_function.SwitchBotClient")
    def test_lock_action_is_not_available_for_fan(self, client_class, _device):
        response = lambda_function.handler({
            "httpMethod": "POST",
            "resource": "/devices/{device}/actions",
            "pathParameters": {"device": "fan"},
            "body": json.dumps({"action": "unlock"}),
            "requestContext": {"authorizer": {
                "sub": "firebase-user-1",
                "email": "owner@example.com",
                "email_verified": "true",
            }},
        }, None)

        self.assertEqual(response["statusCode"], 400)
        client_class.return_value.command.assert_not_called()

    @patch.dict(os.environ, {
        "ALLOWED_EMAILS": "owner@example.com",
        "SWITCHBOT_TOKEN": "token",
        "SWITCHBOT_SECRET": "secret",
    })
    @patch("lambda_function._table")
    @patch("lambda_function.SwitchBotClient")
    def test_device_can_be_registered_from_switchbot_catalog(self, client_class, table):
        client_class.return_value.devices.return_value = [{
            "deviceId": "device-1", "deviceName": "リビング", "deviceType": "Bot",
            "source": "physical",
        }]
        response = lambda_function.handler({
            "httpMethod": "PUT",
            "resource": "/devices/{device}",
            "pathParameters": {"device": "照明"},
            "body": json.dumps({"deviceId": "device-1", "kind": "power"}),
            "requestContext": {"authorizer": {
                "sub": "firebase-user-1", "email": "owner@example.com",
                "email_verified": "true",
            }},
        }, None)

        self.assertEqual(response["statusCode"], 200)
        table.return_value.put_item.assert_called_once()


if __name__ == "__main__":
    unittest.main()
