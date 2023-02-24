/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * AuthPolicy receives a set of allowed and denied methods and generates a valid
 * AWS policy for the API Gateway authorizer. The constructor receives the calling
 * user principal, the AWS account ID of the API owner, and an apiOptions object.
 * The apiOptions can contain an API Gateway RestApi Id, a region for the RestApi, and a
 * stage that calls should be allowed/denied for. For example
 * {
 *   restApiId: "xxxxxxxxxx",
 *   region: "us-east-1",
 *   stage: "dev"
 * }
 *
 * var testPolicy = new AuthPolicy("[principal user identifier]", "[AWS account id]", apiOptions);
 * testPolicy.allowMethod(AuthPolicy.HttpVerb.GET, "/users/username");
 * testPolicy.denyMethod(AuthPolicy.HttpVerb.POST, "/pets");
 * context.succeed(testPolicy.build());
 *
 * This was converted to typescript from the javascript found at the following link on 18/07/2019
 * https://github.com/awslabs/aws-apigateway-lambda-authorizer-blueprints/blob/master/blueprints/nodejs/index.js
 *
 * @class AuthPolicy
 * @constructor
 */

export class AuthPolicy {
  /**
   * A set of existing HTTP verbs supported by API Gateway. This property is here
   * only to avoid spelling mistakes in the policy.
   *
   * @property HttpVerb
   */
  static HttpVerb: Record<TAllowedVerbsKeys, TAllowedVerbsValues> = {
    GET: "GET",
    POST: "POST",
    PUT: "PUT",
    PATCH: "PATCH",
    HEAD: "HEAD",
    DELETE: "DELETE",
    OPTIONS: "OPTIONS",
    ALL: "*",
  };

  private readonly awsAccountId: string;
  private readonly principalId: string;
  private readonly version: string;
  private readonly pathRegex: RegExp;
  private readonly allowMethods: ApiMethod[];
  private readonly denyMethods: ApiMethod[];
  private readonly restApiId: string;
  private readonly region: string;
  private readonly stage: string;

  constructor(
    principal: string,
    awsAccountId: string,
    apiOptions?: ApiOptions
  ) {
    /**
     * The AWS account id the policy will be generated for. This is used to create
     * the method ARNs.
     *
     * @property awsAccountId
     * @type {String}
     */
    this.awsAccountId = awsAccountId;

    /**
     * The principal used for the policy, this should be a unique identifier for
     * the end user.
     *
     * @property principalId
     * @type {String}
     */
    this.principalId = principal;

    /**
     * The policy version used for the evaluation. This should always be "2012-10-17"
     *
     * @property version
     * @type {String}
     * @default "2012-10-17"
     */
    this.version = "2012-10-17";

    /**
     * The regular expression used to validate resource paths for the policy
     *
     * @property pathRegex
     * @type {RegExp}
     * @default '^\/[/.a-zA-Z0-9-\*]+$'
     */
    this.pathRegex = new RegExp("^[/.a-zA-Z0-9-*]+$");

    // these are the internal lists of allowed and denied methods. These are lists
    // of objects and each object has 2 properties: A resource ARN and a nullable
    // conditions statement.
    // the build method processes these lists and generates the approriate
    // statements for the final policy
    this.allowMethods = [];
    this.denyMethods = [];

    if (!apiOptions || !apiOptions.restApiId) {
      this.restApiId = "*";
    } else {
      this.restApiId = apiOptions.restApiId;
    }
    if (!apiOptions || !apiOptions.region) {
      this.region = "*";
    } else {
      this.region = apiOptions.region;
    }
    if (!apiOptions || !apiOptions.stage) {
      this.stage = "*";
    } else {
      this.stage = apiOptions.stage;
    }
  }

  /**
   * Adds an Allow "*" statement to the policy.
   *
   * @method allowAllMethods
   */
  public allowAllMethods = () => {
    this.addMethod.call(this, "Allow", "*", "*", null);
  };

  /**
   * Adds a Deny "*" statement to the policy.
   *
   * @method denyAllMethods
   */
  public denyAllMethods = () => {
    this.addMethod.call(this, "Deny", "*", "*", null);
  };

  /**
   * Adds an API Gateway method (Http verb + Resource path) to the list of allowed
   * methods for the policy
   *
   * @method allowMethod
   * @param verb {String} The HTTP verb for the method, this should ideally come from the
   *                 AuthPolicy.HttpVerb object to avoid spelling mistakes
   * @param resource {string} The resource path. For example "/pets"
   * @return {void}
   */
  public allowMethod = (verb: TAllowedVerbs, resource: string): void => {
    this.addMethod.call(this, "Allow", verb, resource, null);
  };

  /**
   * Adds an API Gateway method (Http verb + Resource path) to the list of denied
   * methods for the policy
   *
   * @method denyMethod
   * @param verb {String} The HTTP verb for the method, this should ideally come from the
   *                 AuthPolicy.HttpVerb object to avoid spelling mistakes
   * @param resource {string} The resource path. For example "/pets"
   * @return {void}
   */
  public denyMethod = (verb: TAllowedVerbs, resource: string): void => {
    this.addMethod.call(this, "Deny", verb, resource, null);
  };

  /**
   * Adds an API Gateway method (Http verb + Resource path) to the list of allowed
   * methods and includes a condition for the policy statement. More on AWS policy
   * conditions here: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html
   *
   * @method allowMethodWithConditions
   * @param verb {String} The HTTP verb for the method, this should ideally come from the
   *                 AuthPolicy.HttpVerb object to avoid spelling mistakes
   * @param resource {string} The resource path. For example "/pets"
   * @param conditions {Object} The conditions object in the format specified by the AWS docs
   * @return {void}
   */
  public allowMethodWithConditions = (
    verb: TAllowedVerbs,
    resource: string,
    conditions: any
  ): void => {
    this.addMethod.call(this, "Allow", verb, resource, conditions);
  };

  /**
   * Adds an API Gateway method (Http verb + Resource path) to the list of denied
   * methods and includes a condition for the policy statement. More on AWS policy
   * conditions here: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html
   *
   * @method denyMethodWithConditions
   * @param verb {String} The HTTP verb for the method, this should ideally come from the
   *                 AuthPolicy.HttpVerb object to avoid spelling mistakes
   * @param resource {string} The resource path. For example "/pets"
   * @param conditions {Object} The conditions object in the format specified by the AWS docs
   * @return {void}
   */
  public denyMethodWithConditions = (
    verb: TAllowedVerbs,
    resource: string,
    conditions: any
  ): void => {
    this.addMethod.call(this, "Deny", verb, resource, conditions);
  };

  /**
   * Generates the policy document based on the internal lists of allowed and denied
   * conditions. This will generate a policy with two main statements for the effect:
   * one statement for Allow and one statement for Deny.
   * Methods that includes conditions will have their own statement in the policy.
   *
   * @method build
   * @return {Object} The policy object that can be serialized to JSON.
   */
  public build = (): IPolicy => {
    if (
      (!this.allowMethods || this.allowMethods.length === 0) &&
      (!this.denyMethods || this.denyMethods.length === 0)
    ) {
      throw new Error("No statements defined for the policy");
    }

    const policy: IPolicy = {
      principalId: this.principalId,
      policyDocument: {
        Version: this.version,
        Statement: [],
      },
    };

    const doc: IPolicyDocument = {
      Version: this.version,
      Statement: [],
    };

    doc.Statement = doc.Statement.concat(
      this.getStatementsForEffect.call(this, "Allow", this.allowMethods)
    );
    doc.Statement = doc.Statement.concat(
      this.getStatementsForEffect.call(this, "Deny", this.denyMethods)
    );

    policy.policyDocument = doc;

    return policy;
  };

  /**
   * Adds a method to the internal lists of allowed or denied methods. Each object in
   * the internal list contains a resource ARN and a condition statement. The condition
   * statement can be null.
   *
   * @method addMethod
   * @param effect {String} The effect for the policy. This can only be "Allow" or "Deny".
   * @param verb {String} he HTTP verb for the method, this should ideally come from the
   *                 AuthPolicy.HttpVerb object to avoid spelling mistakes
   * @param resource {String} The resource path. For example "/pets"
   * @param conditions {Object} The conditions object in the format specified by the AWS docs.
   * @return {void}
   */
  private addMethod = (
    effect: TEffect,
    verb: TAllowedVerbs,
    resource: string,
    conditions: any
  ): void => {
    if (verb !== "*" && !AuthPolicy.HttpVerb[verb]) {
      throw new Error(
        "Invalid HTTP verb " + verb + ". Allowed verbs in AuthPolicy.HttpVerb"
      );
    }

    if (!this.pathRegex.test(resource)) {
      throw new Error(
        "Invalid resource path: " +
          resource +
          ". Path should match " +
          this.pathRegex
      );
    }

    let cleanedResource = resource;
    if (resource.substring(0, 1) === "/") {
      cleanedResource = resource.substring(1, resource.length);
    }
    const resourceArn =
      "arn:aws:execute-api:" +
      this.region +
      ":" +
      this.awsAccountId +
      ":" +
      this.restApiId +
      "/" +
      this.stage +
      "/" +
      verb +
      "/" +
      cleanedResource;

    if (effect.toLowerCase() === "allow") {
      this.allowMethods.push({
        resourceArn,
        conditions,
      });
    } else if (effect.toLowerCase() === "deny") {
      this.denyMethods.push({
        resourceArn,
        conditions,
      });
    }
  };

  /**
   * Returns an empty statement object prepopulated with the correct action and the
   * desired effect.
   *
   * @method getEmptyStatement
   * @param effect {String} The effect of the statement, this can be "Allow" or "Deny"
   * @return {Object} An empty statement object with the Action, Effect, and Resource
   *                  properties prepopulated.
   */
  private getEmptyStatement = (effect: TEffect): IStatement => {
    const statement: IStatement = {
      Action: "execute-api:Invoke",
      Effect: effect,
      Resource: [],
    };

    return statement;
  };

  /**
   * This function loops over an array of objects containing a resourceArn and
   * conditions statement and generates the array of statements for the policy.
   *
   * @method getStatementsForEffect
   * @param effect {String} The desired effect. This can be "Allow" or "Deny"
   * @param methods {Array} An array of method objects containing the ARN of the resource
   *                and the conditions for the policy
   * @return {Array} an array of formatted statements for the policy.
   */
  private getStatementsForEffect = (
    effect: TEffect,
    methods: ApiMethod[]
  ): Array<any> => {
    const statements: IStatement[] = [];

    if (methods.length > 0) {
      const statement = this.getEmptyStatement(effect);

      for (const curMethod of methods) {
        if (
          curMethod.conditions === null ||
          curMethod.conditions.length === 0
        ) {
          statement.Resource.push(curMethod.resourceArn);
        } else {
          const conditionalStatement = this.getEmptyStatement(effect);
          conditionalStatement.Resource.push(curMethod.resourceArn);
          conditionalStatement.Condition = curMethod.conditions;
          statements.push(conditionalStatement);
        }
      }

      if (statement.Resource !== null && statement.Resource.length > 0) {
        statements.push(statement);
      }
    }

    return statements;
  };
}

interface ApiMethod {
  resourceArn: string;
  conditions?: any; //As per https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html
}

export interface ApiOptions {
  restApiId?: string;
  region?: string;
  stage?: string;
}

export interface IStatement {
  Action: string;
  Effect: TEffect;
  Resource: string[];
  Condition?: any;
}

export interface IPolicy {
  principalId: string;
  policyDocument: IPolicyDocument;
  context?: any;
}

export interface IPolicyDocument {
  Version: string;
  Statement: IStatement[];
}

type TAllowedVerbsKeys =
  | "GET"
  | "POST"
  | "PUT"
  | "PATCH"
  | "HEAD"
  | "DELETE"
  | "OPTIONS"
  | "ALL";

type TAllowedVerbsValues =
  | "*"
  | "GET"
  | "POST"
  | "PUT"
  | "PATCH"
  | "HEAD"
  | "DELETE"
  | "OPTIONS";

type TAllowedVerbs = TAllowedVerbsKeys | TAllowedVerbsValues;

type TEffect = "Allow" | "Deny";
