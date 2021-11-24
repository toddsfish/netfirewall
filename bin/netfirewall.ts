#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from '@aws-cdk/core';
import { NetfirewallStack } from '../lib/netfirewall-stack';

const app = new cdk.App();
console.log("Deploy(ed) in......")
console.log(process.env.CDK_DEPLOY_ACCOUNT)
console.log(process.env.CDK_DEPLOY_REGION)

new NetfirewallStack(app, 'NetfirewallStack', {
  /* If you don't specify 'env', this stack will be environment-agnostic.
   * Account/Region-dependent features and context lookups will not work,
   * but a single synthesized template can be deployed anywhere. */

  /* Uncomment the next line to specialize this stack for the AWS Account
   * and Region that are implied by the current CLI configuration. */
  env: { account: process.env.CDK_DEPLOY_ACCOUNT, region: process.env.CDK_DEPLOY_REGION },

  /* Uncomment the next line if you know exactly what Account and Region you
   * want to deploy the stack to. */
  //env: { account: '12345678', region: 'ap-southeast-1' },

  /* For more information, see https://docs.aws.amazon.com/cdk/latest/guide/environments.html */
});
