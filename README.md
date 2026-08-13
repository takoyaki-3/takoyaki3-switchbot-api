# Takoyaki3 SwitchBot Lock API

`takoyaki3-auth` のFirebase Authenticationで認証し、許可されたユーザーだけがSwitchBotスマートロックを操作できるAPIです。

- インフラ: AWS CDK v2 / TypeScript
- API: Amazon API Gateway HTTP API
- 実行環境: AWS Lambda / Python 3.12
- 秘密情報: AWS Secrets Manager

## 認証フロー

1. リバースプロキシで公開したURLを開く
2. Lambdaが `takoyaki3-auth` へリダイレクトする
3. 認証後、`/control?jwt=<Firebase ID token>` へ戻る
4. ブラウザがJWTをURLから除去し、Bearerトークンとして操作APIへ送る
5. API Gateway JWT Authorizerが署名、issuer、audience、有効期限を検証する
6. Lambdaが `sub`、`email_verified`、許可メールアドレスを確認してSwitchBot APIを呼ぶ

## Secrets Manager

次のJSON形式でSwitchBot資格情報を登録してください。

```json
{
  "token": "SwitchBot API token",
  "secret": "SwitchBot API secret",
  "device_id": "SwitchBot lock device ID"
}
```

```powershell
aws secretsmanager create-secret `
  --name takoyaki3/switchbot-lock `
  --secret-string file://switchbot-secret.json
```

登録後はローカルのJSONファイルを安全に削除してください。

## CDKデプロイ

初回のみ依存関係をインストールし、対象アカウント・リージョンをbootstrapします。

```powershell
npm install
npx cdk bootstrap
```

テンプレートを確認します。

```powershell
npm run build
npx cdk synth
```

デプロイ例:

```powershell
npx cdk deploy `
  --parameters SwitchBotSecretArn="arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:takoyaki3/switchbot-lock-xxxxxx" `
  --parameters AllowedEmails="owner@example.com" `
  --parameters PublicBaseUrl="https://lock.takoyaki3.com"
```

パラメータ:

- `SwitchBotSecretArn`: Secrets Managerシークレットの完全なARN（必須）
- `AllowedEmails`: 操作を許可するメールアドレス。複数の場合はカンマ区切り（必須）
- `FirebaseProjectId`: 既定値 `takoyaki3-auth`
- `AuthLoginUrl`: 既定値 `https://takoyaki3-auth.web.app`
- `PublicBaseUrl`: リバースプロキシで公開するHTTPSオリジン。末尾の `/` は付けない

デプロイ後、CloudFormation出力の `ApiUrl` をリバースプロキシの転送先に設定します。利用者が開くURLは `PublicUrl` です。プロキシでは全パスと `Authorization` ヘッダーをAPI Gatewayへ転送してください。

## API

| Method | Path | 認証 | 内容 |
|---|---|---|---|
| GET | `/` | 不要 | `takoyaki3-auth` へリダイレクト |
| GET | `/control` | 不要 | 操作画面 |
| GET | `/status` | Firebase JWT | 状態取得 |
| POST | `/lock` | Firebase JWT | 施錠 |
| POST | `/unlock` | Firebase JWT | 解錠 |

## テスト

```powershell
python -m unittest -v
npm run build
npx cdk synth
```

Firebase IDトークンは最長約1時間有効で、API Gateway JWT AuthorizerはFirebase側の即時失効を照会しません。緊急時は対象ユーザーを `AllowedEmails` から削除して再デプロイしてください。
