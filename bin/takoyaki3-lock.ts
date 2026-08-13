#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { Takoyaki3LockStack } from '../lib/takoyaki3-lock-stack';

const app = new cdk.App();

// AWS CLI/CDKで選択されたアカウントとリージョンをデプロイ先として使用する。
new Takoyaki3LockStack(app, 'Takoyaki3LockStack', {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION,
  },
  description: 'Authenticated SwitchBot lock API for takoyaki3-auth',
});
