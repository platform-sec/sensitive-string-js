/**
 * Wall clock cost of the field-map `preHandler` on a large body.
 *
 * Excluded from `pnpm test` and run with `pnpm test:timing`, because the number
 * depends on how busy the machine is and must not gate a release. What it exists
 * to inform is the open decision under Design Decisions: the field map wraps by
 * clone through core's `wrapSensitiveByPath`, and an in-place variant in core is
 * worth its review cost only if the clone actually shows up.
 *
 * The measurement is per request, so it covers Fastify's own parse and the
 * hook's clone together. A 1 MiB parse dominates both numbers below, and run to
 * run noise on it is larger than the difference between them, so read each as an
 * order of magnitude rather than subtracting one from the other.
 */

// Timing diagnostics are the point of this file.
/* eslint-disable no-console */

import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { describe, expect, test } from 'vitest';
import { sensitivePlugin } from '../plugin.js';
import { bodyOf, buildPlainApp, CANARY, capture } from './fixtures.js';

/** Fastify's default `bodyLimit`. */
const BODY_LIMIT = 1024 * 1024;

/** Requests per measurement. Each is a full parse plus a full clone. */
const REQUESTS = 20;

const FIELDS = {
  'payment.card.number': 'credential',
  'payment.card.cvv': 'credential',
  'payment.holder.email': 'sensitive',
  'items.0.note': 'sensitive',
} as const;

/**
 * A body a little under the default limit, with the configured fields nested
 * inside it and the bulk of the weight in unconfigured data the clone still has
 * to walk.
 */
function buildBody(): Record<string, unknown> {
  const body: Record<string, unknown> = {
    payment: {
      card: { number: CANARY, cvv: '123' },
      holder: { email: 'holder@example.com' },
    },
    items: [] as unknown[],
  };
  const items = body['items'] as unknown[];

  items.push({ note: 'first item', sku: 'SKU-0' });

  while (JSON.stringify(body).length < BODY_LIMIT - 4096) {
    items.push({ sku: `SKU-${items.length}`, description: 'x'.repeat(512), quantity: 1 });
  }

  return body;
}

describe('field map on a body near the default bodyLimit', () => {
  test('wraps within the test timeout, and reports the per-request cost', async () => {
    const app = buildPlainApp();
    const seen = capture<unknown>();
    const body = buildBody();
    const payload = JSON.stringify(body);

    await app.register(sensitivePlugin, { body: FIELDS });

    app.post('/large', async (request) => {
      seen.set(request.body);

      return { ok: true };
    });

    const headers = { 'content-type': 'application/json' };

    // One warm-up request, so the measurement is not paying for the first JIT
    // pass through Fastify's parser and core's clone.
    await app.inject({ method: 'POST', url: '/large', payload, headers });

    const started = process.hrtime.bigint();

    for (let index = 0; index < REQUESTS; index += 1) {
      const response = await app.inject({ method: 'POST', url: '/large', payload, headers });

      expect(response.statusCode).toBe(200);
    }

    const perRequestMs = Number(process.hrtime.bigint() - started) / 1e6 / REQUESTS;

    const wrapped = bodyOf(seen.get());
    const payment = bodyOf(bodyOf(wrapped['payment'])['card']);

    expect(payment['number']).toBeInstanceOf(SensitiveString);
    expect((payment['number'] as SensitiveString<'credential'>).reveal()).toBe(CANARY);

    console.log(
      `body ${(payload.length / 1024).toFixed(0)} KiB, ` +
        `${Object.keys(FIELDS).length} configured fields: ` +
        `${perRequestMs.toFixed(2)} ms per request (parse plus clone)`
    );
  });

  test('an already-wrapped body skips the clone, and reports that cost', async () => {
    const app = buildPlainApp();
    const body = buildBody();
    const payload = JSON.stringify(body);

    // Two registrations: the second finds every configured path already holding
    // an instance and returns without cloning, which is the idempotency path
    // under load rather than under a unit test.
    await app.register(sensitivePlugin, { body: FIELDS });
    await app.register(sensitivePlugin, { body: FIELDS });

    app.post('/large', async () => ({ ok: true }));

    const headers = { 'content-type': 'application/json' };

    await app.inject({ method: 'POST', url: '/large', payload, headers });

    const started = process.hrtime.bigint();

    for (let index = 0; index < REQUESTS; index += 1) {
      await app.inject({ method: 'POST', url: '/large', payload, headers });
    }

    const perRequestMs = Number(process.hrtime.bigint() - started) / 1e6 / REQUESTS;

    console.log(
      'same body, two registrations (one clone, one skip): ' +
        `${perRequestMs.toFixed(2)} ms per request`
    );
  });
});
