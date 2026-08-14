import * as path from 'node:path';
import * as cdk from 'aws-cdk-lib';
import * as apigw from 'aws-cdk-lib/aws-apigateway';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as s3deploy from 'aws-cdk-lib/aws-s3-deployment';
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
    const allowedEmails = new cdk.CfnParameter(this, 'AllowedEmails', {
      type: 'CommaDelimitedList',
      noEcho: true,
      description: 'Firebase email addresses permitted to operate the lock',
    });
    const firebaseProjectId = new cdk.CfnParameter(this, 'FirebaseProjectId', {
      type: 'String',
      default: 'takoyaki3-auth',
    });

    const deviceTable = new dynamodb.Table(this, 'DeviceTable', {
      partitionKey: { name: 'device_name', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: cdk.RemovalPolicy.RETAIN,
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
        DEVICE_TABLE_NAME: deviceTable.tableName,
        ALLOWED_EMAILS: cdk.Fn.join(',', allowedEmails.valueAsList),
      },
    });
    deviceTable.grantReadWriteData(lockFunction);

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
        allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        allowOrigins: apigw.Cors.ALL_ORIGINS,
      },
    });

    // Authorizer拒否やAPI Gateway内部エラーにもCORSヘッダーを付与する。
    const gatewayResponseHeaders = {
      'Access-Control-Allow-Origin': "'*'",
      'Access-Control-Allow-Headers': "'Authorization,Content-Type'",
      'Access-Control-Allow-Methods': "'GET,POST,PUT,DELETE,OPTIONS'",
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

    api.root.addResource('status').addMethod('GET', integration, protectedMethodOptions);
    api.root.addResource('lock').addMethod('POST', integration, protectedMethodOptions);
    api.root.addResource('unlock').addMethod('POST', integration, protectedMethodOptions);
    const devices = api.root.addResource('devices');
    devices.addMethod('GET', integration, protectedMethodOptions);
    const device = devices.addResource('{device}');
    device.addMethod('PUT', integration, protectedMethodOptions);
    device.addMethod('DELETE', integration, protectedMethodOptions);
    device.addResource('status').addMethod('GET', integration, protectedMethodOptions);
    device.addResource('actions').addMethod('POST', integration, protectedMethodOptions);
    api.root.addResource('catalog').addResource('devices')
      .addMethod('GET', integration, protectedMethodOptions);

    const webBucket = new s3.Bucket(this, 'WebBucket', {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    const apiBehavior: cloudfront.BehaviorOptions = {
      origin: new origins.HttpOrigin(
        `${api.restApiId}.execute-api.${this.region}.${this.urlSuffix}`,
        { originPath: '/prod', protocolPolicy: cloudfront.OriginProtocolPolicy.HTTPS_ONLY },
      ),
      viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
      allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
      cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
      originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
    };
    const distribution = new cloudfront.Distribution(this, 'WebDistribution', {
      defaultRootObject: 'index.html',
      defaultBehavior: {
        origin: origins.S3BucketOrigin.withOriginAccessControl(webBucket),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        allowedMethods: cloudfront.AllowedMethods.ALLOW_GET_HEAD_OPTIONS,
        cachePolicy: cloudfront.CachePolicy.CACHING_OPTIMIZED,
        responseHeadersPolicy: cloudfront.ResponseHeadersPolicy.SECURITY_HEADERS,
      },
      additionalBehaviors: {
        'catalog*': apiBehavior,
        'devices*': apiBehavior,
      },
    });
    new s3deploy.BucketDeployment(this, 'DeployWeb', {
      sources: [s3deploy.Source.asset(path.join(__dirname, '..', 'cloudflare-pages'))],
      destinationBucket: webBucket,
      distribution,
      distributionPaths: ['/*'],
    });

    new cdk.CfnOutput(this, 'ApiUrl', {
      description: 'API Gateway origin URL for the reverse proxy',
      value: api.url,
    });
    new cdk.CfnOutput(this, 'WebUrl', {
      description: 'CloudFront default URL for the stateless web UI',
      value: `https://${distribution.distributionDomainName}`,
    });
  }
}
