# aws-api-auth-policy
Typescript implementation of AWS API Gateway Lambda Authorizer policy creator

## Install

```sh
$ npm install XXXXXX
```

## Input

```ts
import {ApiOptions, AuthPolicy} from "XXXX";

const userId = "12345";
const awsAccountId = "6789";

const apiOptions: ApiOptions = {};
apiOptions.region = "region"; //eg us-east-1
apiOptions.restApiId = "restApiId";
apiOptions.stage = "stage";

var authPolicy = new AuthPolicy(userId, awsAccountId, apiOptions);
authPolicy.allowAllMethods();
var generated = authPolicy.build();

var policyJson = JSON.stringify(generated);
console.log(policyJson);
```

## Output

```json
{
  "principalId": "12345",
  "policyDocument": {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": "execute-api:Invoke",
        "Effect": "Allow",
        "Resource": [
          "arn:aws:execute-api:region:6789:restApiId/stage/*/*"
        ]
      }
    ]
  }
}
```
