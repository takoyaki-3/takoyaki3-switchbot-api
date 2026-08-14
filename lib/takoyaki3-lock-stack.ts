import * as path from 'node:path';
import * as cdk from 'aws-cdk-lib';
import * as apigwv2 from 'aws-cdk-lib/aws-apigatewayv2';
import { HttpJwtAuthorizer } from 'aws-cdk-lib/aws-apigatewayv2-authorizers';
import { HttpLambdaIntegration } from 'aws-cdk-lib/aws-apigatewayv2-integrations';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { Construct } from 'constructs';

export class Takoyaki3LockStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // 環境ごとに変わる値はCloudFormationパラメータで受け取り、ソースへ埋め込まない。
    const switchBotSecretArn = new cdk.CfnParameter(this, 'SwitchBotSecretArn', {
      type: 'String',
      noEcho: true,
      description: 'ARN of a Secrets Manager secret containing token, secret, and device_id',
      allowedPattern: '^arn:[^:]+:secretsmanager:[^:]+:[0-9]{12}:secret:.+$',
    });
    const allowedEmails = new cdk.CfnParameter(this, 'AllowedEmails', {
      type: 'CommaDelimitedList',
      description: 'Firebase email addresses permitted to operate the lock',
    });
    const firebaseProjectId = new cdk.CfnParameter(this, 'FirebaseProjectId', {
      type: 'String',
      default: 'takoyaki3-auth',
    });
    const authLoginUrl = new cdk.CfnParameter(this, 'AuthLoginUrl', {
      type: 'String',
      default: 'https://takoyaki3-auth.web.app',
      allowedPattern: '^https://[^/]+(?:/.*)?$',
    });
    const publicBaseUrl = new cdk.CfnParameter(this, 'PublicBaseUrl', {
      type: 'String',
      default: 'https://lock.takoyaki3.com',
      description: 'Public HTTPS URL exposed by the reverse proxy (without trailing slash)',
      allowedPattern: '^https://[^/]+$',
    });

    // Lambdaコード専用ディレクトリをそのままデプロイパッケージにする。
    const lockFunction = new lambda.Function(this, 'LockFunction', {
      runtime: lambda.Runtime.PYTHON_3_12,
      architecture: lambda.Architecture.ARM_64,
      handler: 'lambda_function.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '..', 'lambda')),
      timeout: cdk.Duration.seconds(15),
      memorySize: 128,
      environment: {
        SWITCHBOT_SECRET_ARN: switchBotSecretArn.valueAsString,
        ALLOWED_EMAILS: cdk.Fn.join(',', allowedEmails.valueAsList),
        AUTH_LOGIN_URL: authLoginUrl.valueAsString,
        PUBLIC_BASE_URL: publicBaseUrl.valueAsString,
      },
    });

    // SwitchBot資格情報を格納した指定シークレットだけに読み取り権限を限定する。
    lockFunction.addToRolePolicy(new iam.PolicyStatement({
      actions: ['secretsmanager:GetSecretValue'],
      resources: [switchBotSecretArn.valueAsString],
    }));

    // リバースプロキシの転送先となるHTTP API。ステージ名をURLへ含めない。
    const api = new apigwv2.HttpApi(this, 'LockApi', {
      createDefaultStage: false,
      description: 'Firebase-authenticated SwitchBot lock API',
    });
    new apigwv2.HttpStage(this, 'DefaultStage', {
      httpApi: api,
      stageName: '$default',
      autoDeploy: true,
      throttle: {
        burstLimit: 2,
        rateLimit: 1,
      },
    });

    const integration = new HttpLambdaIntegration('LockIntegration', lockFunction);
    // Firebase IDトークンの署名・issuer・audience・有効期限をAPI Gatewayで検証する。
    const authorizer = new HttpJwtAuthorizer(
      'FirebaseAuthorizer',
      `https://securetoken.google.com/${firebaseProjectId.valueAsString}`,
      { jwtAudience: [firebaseProjectId.valueAsString] },
    );

    // 認証開始と操作画面の配信は公開し、実際の鍵操作だけJWTを必須にする。
    api.addRoutes({ path: '/', methods: [apigwv2.HttpMethod.GET], integration });
    api.addRoutes({ path: '/control', methods: [apigwv2.HttpMethod.GET], integration });
    api.addRoutes({
      path: '/status',
      methods: [apigwv2.HttpMethod.GET],
      integration,
      authorizer,
    });
    api.addRoutes({
      path: '/lock',
      methods: [apigwv2.HttpMethod.POST],
      integration,
      authorizer,
    });
    api.addRoutes({
      path: '/unlock',
      methods: [apigwv2.HttpMethod.POST],
      integration,
      authorizer,
    });

    new cdk.CfnOutput(this, 'ApiUrl', {
      description: 'API Gateway origin URL for the reverse proxy',
      value: api.apiEndpoint,
    });
    new cdk.CfnOutput(this, 'PublicUrl', {
      description: 'Public URL to open in a browser',
      value: publicBaseUrl.valueAsString,
    });
  }
}
