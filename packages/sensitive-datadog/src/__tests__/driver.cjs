/*
 * One `dd-trace` process, driven end to end.
 *
 * Run by `fixtures.ts`, never by a person. argv[2] is a `DriverSpec` as JSON;
 * the result is one `SENSITIVE_DRIVER_RESULT` line on stdout.
 *
 * CommonJS, and a child process, for the same reason the New Relic driver is:
 * the agent patches modules on the way in and configures itself once, so one
 * process can only be one case. There is a second reason here, and it is the
 * one that decides it. `dd-trace`'s CJS instrumentation hook does not install
 * under an ESM entry point, which is what a Vitest worker is; measured, a
 * tracer initialized inside a worker loads the `http` plugin and never patches
 * `Server.prototype.emit`, so every span the suite is about is simply absent.
 * The agent's own answer to that is `--import dd-trace/initialize.mjs`, which
 * is a different code path from the one this package supports. So the suite
 * runs the supported one, in a process shaped like the deployments it is for.
 */
'use strict';

const spec = JSON.parse(process.argv[2] || '{}');
const CANARY = spec.canary;

if (typeof CANARY !== 'string' || CANARY === '') {
  throw new Error('the driver spec needs a canary');
}

const result = { hookCalls: [], userHookCalls: 0, degraded: [], reports: [], notes: {} };

/**
 * Variant A of the load-order measurement: `http` required before `init()`.
 *
 * With `install: false` this reproduces the silently broken deployment. With
 * an install it reproduces the repair, because `installSensitiveScrubbing`
 * re-requires the core modules and the agent patches the shared object in
 * place for every reference already handed out.
 */
const preHttp = spec.preRequireHttp ? require('http') : null;

const tracer = require('dd-trace');

function initTracer() {
  tracer.init({
    service: 'sensitive-datadog-probe',
    url: spec.agentUrl,
    flushInterval: 100,
    startupLogs: false,
    logLevel: 'error',
    plugins: true,
    ...(spec.headerTags ? { headerTags: spec.headerTags } : {}),
    ...(spec.queryStringObfuscation === undefined
      ? {}
      : { queryStringObfuscation: spec.queryStringObfuscation }),
  });
}

function installUserHook() {
  if (!spec.userHook) return;

  tracer.use('http', {
    headers: spec.headerTags || [],
    hooks: {
      request(span) {
        result.userHookCalls += 1;
        if (span) span.setTag('probe.user_hook', 'ran');
      },
    },
  });
}

function install() {
  if (!spec.install) return;

  const { installSensitiveScrubbing } = require('../../dist/install.js');

  result.notes.installation = installSensitiveScrubbing(tracer, {
    ...(spec.installOptions || {}),
    ...(spec.hostileRecognizer ? { denyValues: [hostileRecognizer()] } : {}),
    onScrub(report) {
      result.reports.push({
        kind: report.kind,
        instances: report.instances,
        classes: [...report.classes],
        deniedKeys: [...report.deniedKeys],
        markersSeen: report.markersSeen,
        failed: report.failed,
        ...(report.labels ? { labels: [...report.labels] } : {}),
      });
    },
    onDegraded(message) {
      result.degraded.push(message);
    },
  });
}

async function main() {
  if (spec.installBeforeInit) {
    installUserHook();
    install();
    initTracer();
  } else {
    initTracer();
    installUserHook();
    install();
  }

  if (spec.applicationTags) {
    writeApplicationTags();
  }

  if (spec.request !== false) {
    await makeRequest();
  }

  // Give the agent time to flush. There is no public flush on the tracer, and
  // `flushInterval` is 100ms above.
  await new Promise((resolve) => setTimeout(resolve, spec.settleMs || 900));

  process.stdout.write(`SENSITIVE_DRIVER_RESULT ${JSON.stringify(result)}\n`);
  process.exit(0);
}

/**
 * A caller value recognizer that throws, which is the one unguarded thing in a
 * policy. `compileValuePatterns` keeps a caller `RegExp` as given when its
 * flags carry no `g` or `y`, and `matchValue` calls `test` on it.
 */
function hostileRecognizer() {
  const pattern = /never/;

  Object.defineProperty(pattern, 'test', {
    value() {
      throw new Error('hostile recognizer');
    },
  });

  return pattern;
}

/** The 2.3 and 2.4 positions: a wrapped value and a wire-format object on a tag. */
function writeApplicationTags() {
  const { SensitiveString } = require('@platform-sec/sensitive-string-core');
  const secret = new SensitiveString(CANARY, 'credential', 'tok');
  const unlabelled = new SensitiveString(CANARY, 'credential');

  const span = tracer.startSpan('probe.tags');

  span.setTag('probe.wrapped', secret);
  span.setTag('probe.unlabelled', unlabelled);
  span.setTag('probe.serialized', secret.serialize());
  span.setTag('probe.plain', 'keep-me');
  span.setTag('probe.password', CANARY);
  span.setTag('probe.url', `https://api.test/v1/pay?token=${CANARY}&page=2`);
  span.setTag('probe.nested', { token: secret, note: 'keep-me' });
  span.setTag('error.message', `failed for ${secret}`);

  span.finish();
}

async function makeRequest() {
  const http = preHttp || require('http');
  const server = spec.framework === 'express' ? expressServer() : plainServer(http);
  const listening = await server.listen();

  try {
    await new Promise((resolve, reject) => {
      const client = http.request(
        {
          host: '127.0.0.1',
          port: listening,
          method: 'POST',
          // `token` is covered by the agent's own default obfuscator; `cookie`
          // is not, and is what the composed pattern adds.
          path: `/pay?token=${CANARY}&cookie=${CANARY}&page=2`,
          headers: {
            authorization: `Bearer ${CANARY}`,
            cookie: `session=${CANARY}`,
            'x-api-key': CANARY,
            'x-trace': 'keep-me',
            'content-type': 'application/json',
          },
        },
        (response) => {
          response.resume();
          response.on('end', resolve);
        }
      );

      client.on('error', reject);
      client.end(JSON.stringify({ password: CANARY }));
    });
  } finally {
    await server.close();
  }
}

function plainServer(http) {
  const server = http.createServer((request, response) => {
    response.setHeader('x-api-key', CANARY);
    response.setHeader('x-trace', 'keep-me');
    response.statusCode = 500;
    response.end('no');
  });

  return wrap(server);
}

function expressServer() {
  const express = require('express');
  const app = express();

  app.post('/pay', (request, response) => {
    response.setHeader('x-api-key', CANARY);
    response.setHeader('x-trace', 'keep-me');
    response.status(500).send('no');
  });

  let server;

  return {
    listen: () =>
      new Promise((resolve) => {
        server = app.listen(0, '127.0.0.1', () => resolve(server.address().port));
      }),
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

function wrap(server) {
  return {
    listen: () =>
      new Promise((resolve) => {
        server.listen(0, '127.0.0.1', () => resolve(server.address().port));
      }),
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
