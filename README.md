# Takoyaki3 SwitchBot API

Firebase Authenticationで認証した許可ユーザーが、SwitchBotデバイスを参照・操作するAPIと、最小構成のWeb UIです。

- API: API Gateway REST API + Python 3.12 Lambda
- デバイス情報: SwitchBot APIから都度取得
- 一括操作設定: DynamoDBにデバイスID単位で保存
- Web UI: 非公開S3バケット + CloudFront Origin Access Control
- 認証: Firebase JWTを検証するLambda Authorizer
- デプロイ: AWS CDK / GitHub Actions OIDC

## デバイス構成

デバイスID・名称・種別はソースやGitHub Secretsへ固定しません。`GET /devices`がSwitchBot APIの一覧を取得し、SwitchBotアプリで設定した`deviceName`を名称として返します。

操作能力は`deviceType`と物理／赤外線の区分から自動判定します。

- `lock`: `lock`／`unlock`
- `power`: `on`／`off`（SwitchBotへは`turnOn`／`turnOff`を送信）
- `readonly`: 状態参照のみ、または現在のAPIでは操作対象外

SwitchBotの任意コマンドを中継する仕様にはしていません。Keypadやセンサーなどは誤操作を避けるため`readonly`になります。

## API

詳細は[openapi.yaml](openapi.yaml)を参照してください。

| Method | Path | 内容 |
|---|---|---|
| GET | `/devices` | SwitchBot名称、種別、自動判定した操作能力の一覧 |
| GET | `/devices/{deviceId}/status` | 物理デバイスの状態取得 |
| POST | `/devices/{deviceId}/actions` | 自動判定された範囲内で操作 |
| PUT | `/devices/{deviceId}/settings` | 一括操作対象フラグをDynamoDBへ保存 |
| POST | `/bulk-actions/home-on` | APIに設定された対象を一括操作 |

互換用の`/status`、`/lock`、`/unlock`は、一覧で最初に見つかった`lock`種別のデバイスを操作します。他の統合UIも同じAPIを利用できます。CORSは全オリジン（`*`）を許可します。

## Web UI

`cloudflare-pages/index.html`はディレクトリ名を互換のため残していますが、CDKがS3へ配置しCloudFrontで配信します。CloudFormation出力`WebUrl`がCloudFrontのデフォルトURLです。独自ドメインや証明書は作成しません。

UIは以下をブラウザストレージへ保存しないステートレス構成です。

- JWTがない場合: `http://takoyaki3-auth.web.app/?r=https://home-switchbot.app.takoyaki3.com/`へ自動リダイレクト
- JWT付きで戻った場合: `?jwt=...`をメモリへ取り込み、即座にブラウザのURLから削除して自動接続
- JWTの保持: JavaScriptメモリ内だけ。再読み込み・タブ終了時に破棄
- 期限切れ・署名不正・形式不正のJWT: Lambda Authorizerの検証によりAPIが`401 Unauthorized`を返し、UIがJWTを破棄して認証画面へ自動リダイレクト
- 許可リスト外のユーザー: 有効なJWTでも`403 Forbidden`を画面に表示し、認証画面とのリダイレクトループを防止
- デバイス一覧: 毎回SwitchBot APIから取得
- 一括操作設定: HTMLには保存せず、APIを通じてDynamoDBから取得・更新
- API URL: CloudFrontの`devices*`／`bulk-actions*`ビヘイビアで同一オリジンからAPI Gatewayへ転送
- スマートフォン表示: 1カラムのデバイスカードと大きなタップ領域に切り替え、画面端のセーフエリアにも対応
- 表示順: ロックを常に一覧の先頭へ表示
- 一括操作対象: 各デバイスカードからAPIへ設定し、ロックは解錠、電源デバイスはONとして保存
- 一括操作: 画面上部のボタンは`POST /bulk-actions/home-on`を1回だけ呼び、API側がDynamoDBの設定を読み取って実行

一括対象の選択、対象デバイスID、実行する操作の判定はすべてAPI側にあります。HTMLが保持するのは表示中のAPIレスポンスとJWTだけで、`localStorage`や`sessionStorage`は使用しません。別の統合UIから同じ設定API・一括操作APIを利用した場合も同じ結果になります。

DynamoDBテーブルはオンデマンド課金、AWS管理暗号化、ポイントインタイムリカバリ、削除時保持で構築します。以前の版で作成され、CloudFormationから既に切り離されたテーブルがある場合、それは新しい設定テーブルとは別に保持されます。

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
