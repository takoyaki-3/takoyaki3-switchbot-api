# Takoyaki3 SwitchBot Lock API

`takoyaki3-auth` のFirebase Authenticationで認証し、許可されたユーザーだけがSwitchBotスマートロックを操作できるAPIです。

- インフラ: AWS CDK v2 / TypeScript
- API: Amazon API Gateway HTTP API
- 実行環境: AWS Lambda / Python 3.12
- 秘密情報: GitHub Actions SecretsからLambda環境変数へ設定

## 認証フロー

1. リバースプロキシで公開したURLを開く
2. Lambdaが `takoyaki3-auth` へリダイレクトする
3. 認証後、`/control?jwt=<Firebase ID token>` へ戻る
4. ブラウザがJWTをURLから除去し、Bearerトークンとして操作APIへ送る
5. API Gateway JWT Authorizerが署名、issuer、audience、有効期限を検証する
6. Lambdaが `sub`、`email_verified`、許可メールアドレスを確認してSwitchBot APIを呼ぶ

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
  --parameters SwitchBotToken="SwitchBot API token" `
  --parameters SwitchBotSecret="SwitchBot API secret" `
  --parameters SwitchBotDeviceId="SwitchBot lock device ID" `
  --parameters AllowedEmails="owner@example.com" `
  --parameters PublicBaseUrl="https://lock.takoyaki3.com"
```

パラメータ:

- `SwitchBotToken`: SwitchBot APIトークン（必須）
- `SwitchBotSecret`: SwitchBot API署名用シークレット（必須）
- `SwitchBotDeviceId`: SwitchBotロックのデバイスID（必須）
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

## GitHub Actionsによる自動デプロイ

`.github/workflows/deploy.yml` は `main` ブランチへのpush、または手動実行でCDKスタックをデプロイします。AWSの長期アクセスキーは使用せず、GitHub OIDCでIAMロールを引き受けます。

GitHubリポジトリに次の設定を登録してください。

Repository Variables:

- `AWS_ROLE_ARN`: GitHub Actionsが引き受けるIAMロールのARN

Repository Secrets:

- `SWITCHBOT_TOKEN`: SwitchBot APIトークン
- `SWITCHBOT_SECRET`: SwitchBot API署名用シークレット
- `SWITCHBOT_DEVICE_ID`: SwitchBotロックのデバイスID
- `ALLOWED_EMAILS`: 操作を許可するメールアドレス。複数指定する場合は、空白を入れずカンマで区切ります（例: `owner@example.com,family@example.com,staff@example.com`）

これらの値はGitHub Actionsから`NoEcho`付きCloudFormationパラメータとして渡され、Lambda環境変数に設定されます。AWS Secrets ManagerやSSM Parameter Storeには保存しません。

デプロイ先リージョンは東京リージョン（`ap-northeast-1`）に固定されています。

AWS IAMにOIDCプロバイダーを作成します。

- Provider URL: `https://token.actions.githubusercontent.com`
- Audience: `sts.amazonaws.com`

IAMロールの信頼ポリシーは、このリポジトリの `main` ブランチだけを許可します。`AWS_ACCOUNT_ID` は実際のAWSアカウントIDへ置き換えてください。

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::AWS_ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "repo:takoyaki-3/takoyaki3-switchbot-api:ref:refs/heads/main"
        }
      }
    }
  ]
}
```

このIAMロールには、CDK bootstrapで作成されたデプロイロールとファイル公開ロールを引き受ける権限など、CDKデプロイに必要な権限を付与してください。
