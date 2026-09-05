import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { gunzipSync } from 'node:zlib';

import * as Sentry from '@sentry/node';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import {
  createCanary,
  expectCanaryPresent,
  expectNoCanary,
} from '@platform-sec/sensitive-string-scrub/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { withSensitiveScrubbing } from '../install.js';
import { runIsolated } from './fixtures.js';

/**
 * The transport-level assertion, which the design's Q2 leaves as a test-only
 * measure.
 *
 * Q2 asks whether these packages should wrap the vendor's transport instead of
 * its hooks, and answers no: at the transport the payload is bytes, the
 * structure the denylist matches on is gone, and reconstructing it means a
 * version-coupled parser in a security-critical path. What it does leave open
 * is a cheap final check in tests, and this is it.
 *
 * The rest of the Sentry suite asserts on the envelope object a capturing
 * transport receives. That is one step short of the wire: the SDK still has to
 * serialize the envelope and may compress it. This drives the SDK's own HTTP
 * transport at a server on loopback and searches the bytes that actually left
 * the process, which is the only assertion in this package that no code of this
 * repository's is involved in producing.
 *
 * The Bugsnag and Rollbar packages assert this way throughout rather than as an
 * extra case, because for those vendors a scrubbing pass runs inside the
 * encoder and an assertion on the payload object cannot see it.
 */

interface Received {
  readonly bodies: Buffer[];
  text(): string;
}

let server: Server;
let received: Received;
let dsn: string;

beforeEach(async () => {
  const bodies: Buffer[] = [];

  server = createServer((request, response) => {
    const chunks: Buffer[] = [];

    request.on('data', (chunk: Buffer) => chunks.push(chunk));
    request.on('end', () => {
      bodies.push(Buffer.concat(chunks));
      response.writeHead(200, { 'Content-Type': 'application/json' });
      response.end('{}');
    });
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

  const { port } = server.address() as AddressInfo;

  dsn = `http://abc@127.0.0.1:${String(port)}/1`;
  received = {
    bodies,
    text() {
      // The SDK gzips an envelope above a size threshold and sends it plain
      // below one, and which applies depends on how much the fixture put in it.
      // Both are decoded here rather than assuming either.
      return bodies
        .map((body) => {
          try {
            return gunzipSync(body).toString('utf8');
          } catch {
            return body.toString('utf8');
          }
        })
        .join('\n');
    },
  };
});

afterEach(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe('the bytes that leave the process', () => {
  // TEST-SENTRY-TRANSPORT
  it('carries no canary from any position the sweep covers', async () => {
    const canary = createCanary('wire');

    await runIsolated(
      withSensitiveScrubbing({
        dsn,
        integrations: [Sentry.requestDataIntegration()] as never,
      }),
      () => {
        Sentry.getCurrentScope().setSDKProcessingMetadata({
          normalizedRequest: {
            url: `http://127.0.0.1:8080/pay?token=${canary}&page=2`,
            method: 'POST',
            headers: { authorization: `Bearer ${canary}`, 'x-trace': 'keep-me' },
            data: { client_secret: canary },
          },
        });
        Sentry.getCurrentScope().setExtra('access_token', canary);
        Sentry.getCurrentScope().setExtra(
          'wire',
          new SensitiveString(canary, 'credential').serialize()
        );
        Sentry.addBreadcrumb({ message: 'auth', data: { refresh_token: canary } });
        Sentry.captureException(new Error('boom'));
      }
    );

    expect(received.bodies.length).toBeGreaterThan(0);
    expectNoCanary(received.text(), canary, 'the serialized envelope');

    // The route survived, so the scrub kept what makes the report useful.
    expect(received.text()).toContain('/pay');
    expect(received.text()).toContain('keep-me');
  });

  // TEST-SENTRY-TRANSPORT-LEAKS
  it('proves the fixture reaches the wire by leaking without the scrubbing', async () => {
    // A byte-level assertion that only checks absence would keep passing if the
    // envelope never arrived, or arrived empty, or arrived in an encoding this
    // file cannot read.
    const canary = createCanary('bare');

    await runIsolated({ dsn, integrations: [Sentry.requestDataIntegration()] as never }, () => {
      Sentry.getCurrentScope().setExtra('access_token', canary);
      Sentry.captureException(new Error('boom'));
    });

    expectCanaryPresent(received.text(), canary, 'the serialized envelope');
  });
});
