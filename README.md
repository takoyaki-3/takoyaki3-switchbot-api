# Takoyaki3 SwitchBot API

Firebase Authenticationで認証した許可ユーザーが、SwitchBotデバイスを登録・参照・操作するAPIと、最小構成のWeb UIです。

- API: API Gateway REST API + Python 3.12 Lambda
- デバイス設定: DynamoDB（任意名称とSwitchBotデバイスIDの対応）
- Web UI: 非公開S3バケット + CloudFront Origin Access Control
- 認証: Firebase JWTを検証するLambda Authorizer
- デプロイ: AWS CDK / GitHub Actions OIDC

## デバイス構成

デバイスIDはソースやGitHub Secretsへ固定しません。デプロイ後、許可ユーザーが次のAPIまたはWeb UIから設定します。

1. `GET /catalog/devices`でSwitchBotアカウントのデバイス一覧を取得
2. `PUT /devices/{任意名称}`へ`{"deviceId":"...","kind":"lock"}`または`kind: "power"`を送信
3. 設定はDynamoDBに保存され、`GET /devices`からすべてのクライアントが参照

`kind=lock`では`lock`／`unlock`、`kind=power`では`on`／`off`のみ実行できます。SwitchBotの任意コマンドを中継する仕様にはしていません。デバイスIDを含む設定情報は秘密情報ではありませんが、すべての設定APIをFirebase JWTと許可メールアドレスで保護しています。

## API

詳細は[openapi.yaml](openapi.yaml)を参照してください。

| Method | Path | 内容 |
|---|---|---|
| GET | `/catalog/devices` | SwitchBotデバイス一覧 |
| GET | `/devices` | 設定済み論理デバイス一覧 |
| PUT | `/devices/{device}` | 任意名称でデバイスを登録・更新 |
| DELETE | `/devices/{device}` | デバイス設定を削除 |
| GET | `/devices/{device}/status` | 状態取得 |
| POST | `/devices/{device}/actions` | 操作 |

互換用の`/status`、`/lock`、`/unlock`は、論理名称`lock`に設定したデバイスを操作します。他の統合UIも同じAPIを利用できます。CORSは全オリジン（`*`）を許可します。

## Web UI

`cloudflare-pages/index.html`はディレクトリ名を互換のため残していますが、CDKがS3へ配置しCloudFrontで配信します。CloudFormation出力`WebUrl`がCloudFrontのデフォルトURLです。独自ドメインや証明書は作成しません。

UIは以下をブラウザストレージへ保存しないステートレス構成です。

- JWT: JavaScriptメモリ内だけに保持し、再読み込み・タブ終了時に破棄
- デバイス設定: 毎回APIから取得し、DynamoDBを唯一の保存先とする
- API URL: CloudFrontの`catalog*`／`devices*`ビヘイビアで同一オリジンからAPI Gatewayへ転送

## ローカル確認とデプロイ

```powershell
npm install
npm run build
python -m unittest -v
npx cdk synth
```

手動デプロイ例:

```powershell
npx cdk bootstrap
npx cdk deploy Takoyaki3LockStack `
  --parameters SwitchBotToken="SwitchBot API token" `
  --parameters SwitchBotSecret="SwitchBot API secret" `
  --parameters AllowedEmails="owner@example.com,family@example.com"
```

リージョンは東京（`ap-northeast-1`）です。`AllowedEmails`を複数指定する場合は、空白を入れずカンマで区切ります。

## GitHub Actions

`.github/workflows/deploy.yml`は`main`へのpushまたは手動実行でCDKスタックをデプロイします。Repository Secretsは次の4つです。

- `AWS_ROLE_ARN`: OIDCで引き受けるIAMロール（例: `arn:aws:iam::562487498525:role/GitHubActionsOpenIDConnect`）
- `SWITCHBOT_TOKEN`
- `SWITCHBOT_SECRET`
- `ALLOWED_EMAILS`: 例 `owner@example.com,family@example.com,staff@example.com`

AWSの長期アクセスキー、Secrets Manager、SSM Parameter Storeは使用しません。SwitchBotトークンとシークレットは`NoEcho`付きCloudFormationパラメータを経由してLambda環境変数に設定します。

OIDCロールの信頼ポリシーでは、実際のGitHub OIDCトークンに合わせて次の`sub`を許可します。

```json
{
  "StringEquals": {
    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
    "token.actions.githubusercontent.com:sub": "repo:takoyaki-3@36257738/takoyaki3-switchbot-api@1333260450:ref:refs/heads/main"
  }
}
```

デプロイ後の出力確認:

```powershell
aws cloudformation describe-stacks `
  --stack-name Takoyaki3LockStack `
  --region ap-northeast-1 `
  --query "Stacks[0].Outputs"
```

APIの読み取り確認は`python scripts/verify_deployment.py`を実行し、質問されたらFirebase JWTを貼り付けます。
