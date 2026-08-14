import * as path from 'node:path';
import * as cdk from 'aws-cdk-lib';
import * as apigw from 'aws-cdk-lib/aws-apigateway';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { Construct } from 'constructs';

export class Takoyaki3LockStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // 環境ごとに変わる値はCloudFormationパラメータで受け取り、ソースへ埋め込まない。
    const switchBotToken = new cdk.CfnParameter(this, 'SwitchBotToken', {
      type: 'String',
      noEcho: true,
      description: 'SwitchBot API token',
    });
    const switchBotSecret = new cdk.CfnParameter(this, 'SwitchBotSecret', {
      type: 'String',
      noEcho: true,
      description: 'SwitchBot API signing secret',
    });
    const switchBotDeviceId = new cdk.CfnParameter(this, 'SwitchBotDeviceId', {
      type: 'String',
      noEcho: true,
      description: 'SwitchBot lock device ID',
    });
    const allowedEmails = new cdk.CfnParameter(this, 'AllowedEmails', {
      type: 'CommaDelimitedList',
      noEcho: true,
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
        SWITCHBOT_TOKEN: switchBotToken.valueAsString,
        SWITCHBOT_SECRET: switchBotSecret.valueAsString,
        SWITCHBOT_DEVICE_ID: switchBotDeviceId.valueAsString,
        ALLOWED_EMAILS: cdk.Fn.join(',', allowedEmails.valueAsList),
        AUTH_LOGIN_URL: authLoginUrl.valueAsString,
        PUBLIC_BASE_URL: publicBaseUrl.valueAsString,
      },
    });

    // REST APIではネイティブJWT Authorizerがないため、同じコードの検証用ハンドラーを使う。
    const authFunction = new lambda.Function(this, 'AuthFunction', {
      runtime: lambda.Runtime.PYTHON_3_12,
      architecture: lambda.Architecture.ARM_64,
      handler: 'lambda_function.authorizer',
      code: lambda.Code.fromAsset(path.join(__dirname, '..', 'lambda')),
      timeout: cdk.Duration.seconds(10),
      memorySize: 128,
      environment: {
        FIREBASE_PROJECT_ID: firebaseProjectId.valueAsString,
      },
    });

    // 旧HTTP APIとは論理IDを分け、CloudFormationで安全に置き換える。
    const api = new apigw.RestApi(this, 'LockRestApi', {
      description: 'Firebase-authenticated SwitchBot lock API',
      endpointTypes: [apigw.EndpointType.REGIONAL],
      deployOptions: {
        stageName: 'prod',
        throttlingBurstLimit: 2,
        throttlingRateLimit: 1,
      },
      defaultCorsPreflightOptions: {
        allowHeaders: ['Authorization', 'Content-Type'],
        allowMethods: ['GET', 'POST', 'OPTIONS'],
        allowOrigins: apigw.Cors.ALL_ORIGINS,
      },
    });

    // Authorizer拒否やAPI Gateway内部エラーにもCORSヘッダーを付与する。
    const gatewayResponseHeaders = {
      'Access-Control-Allow-Origin': "'*'",
      'Access-Control-Allow-Headers': "'Authorization,Content-Type'",
      'Access-Control-Allow-Methods': "'GET,POST,OPTIONS'",
    };
    api.addGatewayResponse('Default4xxResponse', {
      type: apigw.ResponseType.DEFAULT_4XX,
      responseHeaders: gatewayResponseHeaders,
    });
    api.addGatewayResponse('Default5xxResponse', {
      type: apigw.ResponseType.DEFAULT_5XX,
      responseHeaders: gatewayResponseHeaders,
    });

    const integration = new apigw.LambdaIntegration(lockFunction);
    const authorizer = new apigw.TokenAuthorizer(this, 'FirebaseAuthorizer', {
      handler: authFunction,
      identitySource: apigw.IdentitySource.header('Authorization'),
      // JWTのexpを毎回評価し、Authorizerキャッシュで期限切れ後も通る時間を作らない。
      resultsCacheTtl: cdk.Duration.seconds(0),
    });
    const protectedMethodOptions: apigw.MethodOptions = {
      authorizer,
      authorizationType: apigw.AuthorizationType.CUSTOM,
    };

    // 認証開始と操作画面の配信は公開し、実際の鍵操作だけJWTを必須にする。
    api.root.addMethod('GET', integration);
    api.root.addResource('control').addMethod('GET', integration);
    api.root.addResource('status').addMethod('GET', integration, protectedMethodOptions);
    api.root.addResource('lock').addMethod('POST', integration, protectedMethodOptions);
    api.root.addResource('unlock').addMethod('POST', integration, protectedMethodOptions);

    new cdk.CfnOutput(this, 'ApiUrl', {
      description: 'API Gateway origin URL for the reverse proxy',
      value: api.url,
    });
    new cdk.CfnOutput(this, 'PublicUrl', {
      description: 'Public URL to open in a browser',
      value: publicBaseUrl.valueAsString,
    });
  }
}
