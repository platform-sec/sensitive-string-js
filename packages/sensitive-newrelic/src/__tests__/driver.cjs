/*
 * One New Relic serverless invocation, in its own process.
 *
 * Run by `fixtures.ts`, never by a person. argv[2] is a directory holding the
 * `newrelic.js` the case is testing; argv[3] is an `InvocationSpec` as JSON.
 *
 * CommonJS on purpose. The agent must be required before the modules it
 * patches, and its own documentation says to require it first; an ESM entry
 * point would put a module graph ahead of it.
 */
'use strict';

const home = process.argv[2];
const spec = JSON.parse(process.argv[3] || '{}');
const CANARY = spec.canary;

if (typeof CANARY !== 'string' || CANARY === '') {
  throw new Error('the invocation spec needs a canary');
}

process.env.NEW_RELIC_HOME = home;
process.env.NEW_RELIC_SERVERLESS_MODE_ENABLED = 'true';
// The agent only starts its Lambda instrumentation when it believes it is in
// Lambda. These are the three variables it reads to decide.
process.env.AWS_LAMBDA_FUNCTION_NAME = 'probe-fn';
process.env.AWS_REGION = 'us-east-1';
process.env.AWS_EXECUTION_ENV = 'AWS_Lambda_nodejs22.x';

const newrelic = require('newrelic');
const { SensitiveString } = require('@platform-sec/sensitive-string-core');

const handler = newrelic.setLambdaHandler(async () => {
  const secret = new SensitiveString(CANARY, 'credential', 'tok');

  if (spec.deniedAttributes) {
    newrelic.addCustomAttributes({
      password: CANARY,
      token: CANARY,
      api_key: CANARY,
      tenant: 'acme',
    });
  }

  if (spec.unnamedAttribute) {
    // A name no denylist covers, which must leak. Without it a sweep that only
    // asserts absence keeps passing when a fixture stops exercising anything.
    newrelic.addCustomAttribute('unnamedByAnyList', CANARY);
  }

  if (spec.wrappedAttribute) {
    newrelic.addCustomAttribute('wrapped', secret);
  }

  if (spec.serializedAttribute) {
    newrelic.addCustomAttribute('serialized', secret.serialize());
  }

  if (spec.coerced) {
    // Already through `sensitiveAttributes`, in the test process where the
    // `SensitiveString` instances live. The output is scalars, so it crosses
    // the process boundary as JSON, and what this proves is the half that
    // matters: a coerced marker reaches the payload where the uncoerced
    // instance would have been dropped.
    newrelic.addCustomAttributes(spec.coerced);
  }

  if (spec.spanAttributes) {
    newrelic.addCustomSpanAttributes(spec.spanAttributes);
  }

  newrelic.noticeError(
    new Error(`failed for ${secret}`),
    spec.errorAttributes ? { password: CANARY, note: 'noticed' } : undefined
  );

  return { statusCode: 500, body: 'no' };
});

const event = {
  httpMethod: 'POST',
  path: '/pay',
  queryStringParameters: { token: CANARY, page: '2' },
  headers: {
    authorization: `Bearer ${CANARY}`,
    cookie: `session=${CANARY}`,
    'x-api-key': CANARY,
    'content-type': 'application/json',
    'user-agent': 'probe',
    host: 'example.test',
  },
  body: JSON.stringify({ password: CANARY }),
  requestContext: { requestId: 'r1', stage: 'prod' },
};

const context = {
  functionName: 'probe-fn',
  awsRequestId: 'a1',
  invokedFunctionArn: 'arn:aws:lambda:us-east-1:1:function:probe-fn',
  getRemainingTimeInMillis: () => 30_000,
};

handler(event, context)
  .then(() => new Promise((resolve) => setTimeout(resolve, 400)))
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
