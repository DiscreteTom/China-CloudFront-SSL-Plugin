import * as cdk from 'aws-cdk-lib';
import {Construct} from 'constructs';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam'
import {
    Aws,
    aws_sns,
    aws_sns_subscriptions,
    CfnParameter,
    aws_events,
    Duration,
    RemovalPolicy
} from "aws-cdk-lib";
import * as targets from 'aws-cdk-lib/aws-events-targets';
import {aws_s3 as s3} from 'aws-cdk-lib';
import {
    Cors,
    Deployment,
    EndpointType,
    LambdaIntegration,
    MethodLoggingLevel,
    RestApi,
    Stage
} from "aws-cdk-lib/aws-apigateway";
import {Effect, PolicyStatement} from "aws-cdk-lib/aws-iam";
import {Schedule} from "aws-cdk-lib/aws-events";

export class ChinaCloudFrontSslPluginStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
        super(scope, id, props);

        this.templateOptions.description = "(SO8156-cn) - China CloudFront SSL Plugin";

        const domainName = new CfnParameter(this, "domainName", {
            type: "String",
            minLength: 1,
            description: "Please input your domain names for applying SSL Certificate, please using commas(,) to separate multiple domains. eg.: www.example.cn,example.cn,*.example.com"
        })

        const emailAddress = new CfnParameter(this, "emailAddress", {
            type: "String",
            minLength: 1,
            description: "Please input your Email address for Email notification.",
            allowedPattern: "\\b[\\w.%+-]+@[\\w.-]+\\.[a-zA-Z]{2,6}\\b",
        })

        const renewIntervalDays = new CfnParameter(this, "renewIntervalDays", {
            type: "Number",
            maxValue: 89,
            minValue: 1,
            default: 80,
            description: "Please input renew interval days between 1 to 89 days, default renew interval days is 80 days."
        })

        this.templateOptions.metadata = {
            "AWS::CloudFormation::Interface": {
                ParameterGroups: [
                    {
                        Parameters: [
                            emailAddress.logicalId,
                            domainName.logicalId,
                            renewIntervalDays.logicalId
                        ]
                    },
                ],
                ParameterLabels: {
                    domainName: {
                        "default": "Domain Name",
                    },
                    emailAddress: {
                        "default": "Email",
                    },
                    renewIntervalDays: {
                        "default": "SSL Renew Interval Days",
                    },
                }
            }
        }

        const cert_topic = new aws_sns.Topic(this, 'Topic', {
            displayName: Aws.STACK_NAME+"-Issue-SSL-Notification",
        });

        cert_topic.addSubscription(new aws_sns_subscriptions.EmailSubscription(emailAddress.valueAsString))

        const cert_bucket = new s3.Bucket(this, 'CertBucket', {
            // bucketName: cert_bucket_name
            removalPolicy: RemovalPolicy.DESTROY
        });

        const certbot_lambda_fn = new lambda.Function(this, 'CertBotFunction', {
            code: lambda.Code.fromAsset('../lambda/CertBot/certbot', {
                bundling: {
                    image: lambda.Runtime.PYTHON_3_10.bundlingImage, // should be 3.12
                    command: [
                        'bash', '-c',
                        'pip install -r requirements.txt -t /asset-output && cp -au . /asset-output'
                    ],
                },
            }),
            runtime: lambda.Runtime.PYTHON_3_10, // should be 3.12
            handler: 'app.handler',
            description: "Core Function for issuing certificates",
            environment: {
                CERTBOT_BUCKET: cert_bucket.bucketName,
                DOMAINS_LIST: domainName.valueAsString,
                DOMAINS_EMAIL: emailAddress.valueAsString,
                STACK_NAME: Aws.STACK_NAME,
                REGION: Aws.REGION,
                TOPIC_ARN: cert_topic.topicArn,
                MAX_DIST_ITEMS: "200",
                DIST_PAGE_SIZE: "20"
            },
            memorySize: 256,
            timeout: Duration.seconds(900),
        });

        certbot_lambda_fn.addToRolePolicy(new iam.PolicyStatement({
            resources: ["*"],
            actions: [
                "cloudfront:GetDistribution",
                "cloudfront:ListDistributions",
                "cloudfront:UpdateDistribution",
                "cloudfront:GetDistributionConfig",
                "route53:GetChange",
                "iam:ListServerCertificates",
                "route53:ListHostedZones"],
            effect: iam.Effect.ALLOW,
        }));
        certbot_lambda_fn.addToRolePolicy(new iam.PolicyStatement({
            resources: [
                "arn:aws-cn:iam::" + Aws.ACCOUNT_ID + ":server-certificate/*",
                "arn:aws-cn:route53:::hostedzone/*",
                cert_bucket.bucketArn,
                cert_bucket.bucketArn + "/*",
                cert_topic.topicArn
            ],
            actions: ["iam:GetServerCertificate",
                "iam:UpdateServerCertificate",
                "iam:ListServerCertificateTags",
                "iam:DeleteServerCertificate",
                "iam:TagServerCertificate",
                "route53:ChangeResourceRecordSets",
                "iam:UntagServerCertificate",
                "iam:UploadServerCertificate",
                "s3:ListBucket",
                "s3:PutObject",
                "s3:GetObject",
                "sns:Publish"
            ],
            effect: iam.Effect.ALLOW,
        }));

        const cfn_created_rule = new aws_events.Rule(this, "CertCfnCreatedRule", {
            description: "Trigger lambda function after stack created",
            enabled: true,
            eventPattern: {
                source: ["aws.cloudformation"],
                detailType: ["CloudFormation Stack Status Change"],
                detail: {
                    "stack-id": [Aws.STACK_ID],
                    "status-details": {
                        "status": ["CREATE_COMPLETE", "UPDATE_COMPLETE"]
                    }
                }
            }
        })
        cfn_created_rule.addTarget(new targets.LambdaFunction(certbot_lambda_fn))

        certbot_lambda_fn.addPermission("CertCfnCreatedEventInvokeLambda", {
            action: "lambda:InvokeFunction",
            principal: new iam.ServicePrincipal("events.amazonaws.com"),
            sourceArn: cfn_created_rule.ruleArn,
        })


        const scheduled_event_rule = new aws_events.Rule(this, "CertScheduledRule", {
            description: "Automatically trigger cert lambda function every " + renewIntervalDays.valueAsNumber + " days",
            enabled: true,
            schedule: Schedule.rate(Duration.days(renewIntervalDays.valueAsNumber))
        })
        scheduled_event_rule.addTarget(new targets.LambdaFunction(certbot_lambda_fn))

        certbot_lambda_fn.addPermission("ScheduledEventsInvokeLambda", {
            action: "lambda:InvokeFunction",
            principal: new iam.ServicePrincipal("events.amazonaws.com"),
            sourceArn: cfn_created_rule.ruleArn,
        })


        /**
         *
         *
         Cert Management
         *
         *
         **/

        const mgmt_rest_api = new RestApi(this, 'SslCertManageAPI', {
            restApiName: Aws.STACK_NAME + ': SSL Cert Management API',
            description: Aws.STACK_NAME + ': SSL Cert Management API',
            deploy: false,
            cloudWatchRole: true,
            defaultCorsPreflightOptions: {
                allowHeaders: [
                    'Content-Type',
                    'X-Amz-Date',
                    'Authorization',
                    'X-Api-Key',
                ],
                allowMethods: ['POST', 'OPTION'],
                allowCredentials: true,
                allowOrigins: Cors.ALL_ORIGINS,
            },
            endpointConfiguration: {
                types: [EndpointType.REGIONAL],
            },
        });


        const invokeUrl = `https://${mgmt_rest_api.restApiId}.execute-api.${Aws.REGION}.amazonaws.com.cn/prod`

        const apiDocFunction = new lambda.Function(this, 'APIExplorerFunction', {
            code: lambda.Code.fromAsset('../lambda/api-explorer', {
                bundling: {
                    image: lambda.Runtime.NODEJS_18_X.bundlingImage,
                    command: [
                        'bash', '-c',
                        'cp -au . /asset-output && cd /asset-output && npm install'
                    ],
                    user: 'root'
                }
            }),
            handler: 'app.handler',
            runtime: lambda.Runtime.NODEJS_18_X,
            description: "API Explorer for management certificates",
            environment: {
                SWAGGER_SPEC_URL: invokeUrl.toString(),
            },
            timeout: Duration.seconds(20),
        });

        const deleteCertFunction = new lambda.Function(this, 'DeleteCertFunction', {
            code: lambda.Code.fromAsset('../lambda/ManageCert/DeleteCert', {
                // bundling: {
                //     image: lambda.Runtime.PYTHON_3_9.bundlingImage,
                //     command: [
                //         'bash', '-c',
                //         'pip install -r requirements.txt -t /asset-output && cp -au . /asset-output'
                //     ],
                // }
            }),
            runtime: lambda.Runtime.PYTHON_3_9,
            handler: 'app.handler',
            description: "API for delete IAM certificates",
            timeout: Duration.seconds(20),
        });

        const listCertFunction = new lambda.Function(this, 'ListCertFunction', {
            code: lambda.Code.fromAsset('../lambda/ManageCert/ListCert', {
                // bundling: {
                //     image: lambda.Runtime.PYTHON_3_9.bundlingImage,
                //     command: [
                //         'bash', '-c',
                //         'pip install -r requirements.txt -t /asset-output && cp -au . /asset-output'
                //     ],
                // }
            }),
            runtime: lambda.Runtime.PYTHON_3_9,
            handler: 'app.handler',
            description: "API for list IAM certificates",
            timeout: Duration.seconds(20),
        });

        deleteCertFunction.addToRolePolicy(
            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: [
                    'iam:DeleteServerCertificate',
                ],
                resources: [
                    '*',
                ],
            }),
        );

        listCertFunction.addToRolePolicy(
            new PolicyStatement({
                effect: Effect.ALLOW,
                actions: [
                    'iam:ListServerCertificates',
                ],
                resources: [
                    '*',
                ],
            }),
        );

        const deployment = new Deployment(this, 'mgmt_deployment', {
            api: mgmt_rest_api,
        });

        const deploymentStage = new Stage(this, 'ssl-cert-prod', {
            stageName: "prod",
            deployment: deployment,
            dataTraceEnabled: true,
            loggingLevel: MethodLoggingLevel.INFO,
        });

        const api_explprer_resource = mgmt_rest_api.root.addResource('api-explorer');
        const proxy = api_explprer_resource.addProxy({
            anyMethod: true,
            defaultIntegration: new LambdaIntegration(apiDocFunction, {proxy: true}),
        });
        const api_explorer_get = api_explprer_resource.addMethod('GET',
            new LambdaIntegration(apiDocFunction, {proxy: true}),
        );

        const delete_resource = mgmt_rest_api.root.addResource('delete-ssl-cert');
        const delete_post = delete_resource.addMethod('POST', new LambdaIntegration(deleteCertFunction, {proxy: true}));

        const list_resource = mgmt_rest_api.root.addResource('list-ssl-cert');
        const list_get = list_resource.addMethod('GET', new LambdaIntegration(listCertFunction, {proxy: true}));


        const s3URL = `https://${Aws.REGION}.console.amazonaws.cn/s3/buckets/${cert_bucket.bucketName}`

        certbot_lambda_fn.addEnvironment("API_EXPLORER",invokeUrl.toString() + '/api-explorer/')

        new cdk.CfnOutput(this, 'S3-Bucket-URL', {
            value: s3URL.toString(),
            description: "Download SSL certification from S3 bucket",
        });

        new cdk.CfnOutput(this, 'Management-Web-URL', {
            value: invokeUrl.toString() + '/api-explorer/',
            description: "For IAM SSL Certification Management API UI"
        });

        new cdk.CfnOutput(this, 'Cloudfront-Console', {
            value: "https://console.amazonaws.cn/cloudfront",
            description: "Check IAM SSL Certification and use it in CloudFront, please find doc on: https://docs.amazonaws.cn/AmazonCloudFront/latest/DeveloperGuide/cnames-and-https-procedures.html#cnames-and-https-updating-cloudfront",
        });

    }
}
