global.fetch = require("node-fetch");

import {
  CognitoUserPool,
  CognitoUser,
  AuthenticationDetails
} from "amazon-cognito-identity-js";
import AWS from "aws-sdk";
import https from "https";
import url from "url";

export const authorize = (event, context, callback) => {
  console.log("Event:", JSON.stringify(event));
  const getSftpPolicy = (username) =>
    JSON.stringify({
      Role: process.env.ROLE_ARN,
      Policy: `{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowListingOfUserFolder",
                "Action": [
                    "s3:ListBucket"
                ],
                "Effect": "Allow",
                "Resource": [` +
                    '"arn:aws:s3:::${transfer:HomeBucket}"' +
                `],
                "Condition": {
                    "StringLike": {
                        "s3:prefix": [` +
                            '"${transfer:UserName}/*",' +
                            '"${transfer:UserName}"' +
                        `]
                    }
                }
            },
            {
                "Sid": "AWSTransferRequirements",
                "Effect": "Allow",
                "Action": [
                    "s3:ListAllMyBuckets",
                    "s3:GetBucketLocation"
                ],
                "Resource": "*"
            },
            {
                "Sid": "HomeDirObjectAccess",
                "Effect": "Allow",
                "Action": [
                    "s3:PutObject",
                    "s3:GetObject",
                    "s3:DeleteObjectVersion",
                    "s3:DeleteObject",
                    "s3:GetObjectVersion"
                ],` +
                '"Resource": "arn:aws:s3:::${transfer:HomeDirectory}*"' +
             `}
        ]
      }`,    
      HomeDirectory: `/${process.env.BUCKET_ARN.substring("arn:aws:s3:::".length)}/${username}/`,
      HomeBucket: process.env.BUCKET_ARN.substring("arn:aws:s3:::".length)
    });
  if (process.env.SERVER_ID !== event.pathParameters.serverId) {
    callback({});
  }
  const cognitoPoolData = {
    UserPoolId: process.env.COGNITO_USER_POOL_ID,
    ClientId: process.env.COGNITO_CLIENT_ID
  };
  const response = {
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Content-Type": "application/json"
    },
    body: {},
    statusCode: 200
  };
  const userPool = new CognitoUserPool(cognitoPoolData);
  const authenticationData = {
    Username: event.pathParameters.user,
    Password: event.headers.Password
  };
  const authenticationDetails = new AuthenticationDetails(authenticationData);
  const cognitoUser = new CognitoUser({
    Username: authenticationData.Username,
    Pool: userPool
  });
  cognitoUser.authenticateUser(authenticationDetails, {
    onSuccess: function(result) {
      response.body = getSftpPolicy(authenticationData.Username);
      console.log(response.body);
      callback(null, response);
    },

    onFailure: function(err) {
      response.body = JSON.stringify(err);
      callback(null, response);
    },
    mfaRequired: function(codeDeliveryDetails) {
      response.body = getSftpPolicy(authenticationData.Username);
      callback(null, response);
    },
    newPasswordRequired: function(userAttributes, requiredAttributes) {
      response.body = getSftpPolicy(authenticationData.Username);
      console.log(response.body);
      callback(null, response);
    }
  });
};

export const manageSftpServer = (event, context, callback) => {
  console.log("Event:", JSON.stringify(event));;
  const properties = event.ResourceProperties;
  const params = {
    IdentityProviderDetails: {
      InvocationRole: properties.InvocationRole,
      Url: properties.AuthorizeUrl
    },
    IdentityProviderType:
      (properties.InvocationRole &&
      properties.AuthorizeUrl &&
      typeof properties.InvocationRole !== "undefined" &&
      typeof properties.AuthorizeUrl !== "undefined")
        ? "API_GATEWAY"
        : "SERVICE_MANAGED",
    LoggingRole: properties.LoggingRole
  };
  if (event.RequestType === "Create") {
    const transfer = new AWS.Transfer();
    console.log("params:", JSON.stringify(params));
    transfer.createServer(params, (err, data) => {
      const responseData = {};
      if (err) {
        console.log(err, err.stack);
        sendResponse(event, context, context.logStreamName, responseData, err);
      } else {
        const resourceId = data.ServerId;
        responseData["ServerId"] = data.ServerId;
        console.log(`The SFTP server #${resourceId} successfully created!`);
        sendResponse(event, context, resourceId, responseData);
      }
    });
  }
  if (event.RequestType === "Update") {
    const transfer = new AWS.Transfer()
    params["ServerId"] = event.PhysicalResourceId;
    delete params.IdentityProviderType;

    transfer.updateServer(params, (error, data) => {
      const responseData = {};
      if (error) {
        console.log(error, error.stack);
        sendResponse(
          event,
          context,
          event.PhysicalResourceId,
          responseData,
          error
        );
      } else {
        const resourceId = data.ServerId;
        responseData["ServerId"] = data.ServerId;
        console.log(`The SFTP server #${resourceId} successfully updated!`);
        sendResponse(event, context, resourceId, responseData);
      }
    });
  }
  if (event.RequestType === "Delete") {
    const transfer = new AWS.Transfer()
    transfer.deleteServer({
      ServerId: event.PhysicalResourceId
    }, (error, data) => {
      if (error) {
        console.log(error, error.stack);
        sendResponse(event, context, event.PhysicalResourceId, {}, error);
      } else {
        console.log(
          `The SFTP server #${event.PhysicalResourceId} successfully deleted!`
        );
        sendResponse(event, context, event.PhysicalResourceId, {});
      }
    });
  }
};
const sendResponse = (event, context, resourceId, responseData, error) => {
  const responseStatus = error ? "FAILED" : "SUCCESS";
  const reasonText = error
    ? `FAILED with error: ${error}`
    : `See the details in CloudWatch Log Stream: ${context.logStreamName}`;

  const responseBody = JSON.stringify({
    Status: responseStatus,
    Reason: reasonText,
    PhysicalResourceId: resourceId,
    StackId: event.StackId,
    RequestId: event.RequestId,
    LogicalResourceId: event.LogicalResourceId,
    Data: responseData
  });

  const parsedUrl = url.parse(event.ResponseURL);
  const options = {
    hostname: parsedUrl.hostname,
    port: 443,
    path: parsedUrl.path,
    method: "PUT",
    headers: {
      "content-type": "",
      "content-length": responseBody.length
    }
  };

  const request = https.request(options, function(response) {
    context.done();
  });

  request.on("error", function(error) {
    console.log("sendResponse Error:" + error);
    context.done();
  });

  request.write(responseBody);
  request.end();
};
