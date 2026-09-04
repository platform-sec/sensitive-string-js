import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { findMarker, startRecordingServer } from '@platform-sec/sensitive-string-http/testing';
import type { RecordingServer } from '@platform-sec/sensitive-string-http/testing';

import { chargeCard, describeReceipt, paymentClientFromEnv } from './outbound-charge.js';
import type { PaymentClient } from './outbound-charge.js';

/**
 * Assertions on the bytes that crossed the socket, not on what the client
 * remembers having been told.
 *
 * The server listens on loopback over plaintext, which the transport check
 * exempts on purpose: a sidecar or a local proxy that terminates TLS itself is
 * the legitimate case, and a suite that had to set `allowInsecureTransport`
 * would be teaching the wrong habit.
 */

const TOKEN = 'LEAKED_TOKEN_abc123xyz';
const PAN = 'LEAKED_PAN_4242424242424242';

let server: RecordingServer;

beforeEach(async () => {
  server = await startRecordingServer({
    status: 200,
    body: JSON.stringify({ id: 'ch_1', customerEmail: 'buyer@example.com' }),
  });
});

afterEach(async () => {
  await server.close();
});

function client(): PaymentClient {
  return {
    endpoint: server.origin,
    apiToken: new SensitiveString(TOKEN, 'credential', 'api_token'),
    cardNumber: new SensitiveString(PAN, 'credential', 'pan'),
  };
}

describe('chargeCard', () => {
  it('sends both revealed values and no marker', async () => {
    await chargeCard(client(), { amount: 4200, currency: 'usd' });

    const recorded = server.requests[0];

    expect(recorded?.headers['authorization']).toBe(`Bearer ${TOKEN}`);
    expect(recorded?.body).toBe(`{"amount":4200,"currency":"usd","card":{"number":"${PAN}"}}`);
    expect(findMarker(server.transcript)).toBeUndefined();
  });

  it('leaves the response email wrapped, so an ordinary log line is already safe', async () => {
    const receipt = await chargeCard(client(), { amount: 1, currency: 'usd' });

    expect(receipt.customerEmail).toBeInstanceOf(SensitiveString);
    expect(describeReceipt(receipt)).toBe('charge ch_1 for [REDACTED:sensitive]');
  });
});

describe('paymentClientFromEnv', () => {
  it('refuses to build a client from a missing variable', () => {
    expect(() => paymentClientFromEnv({})).toThrow(/must be set/);
  });

  it('wraps both values it finds', () => {
    const built = paymentClientFromEnv({
      PAYMENT_API_TOKEN: TOKEN,
      TEST_CARD_NUMBER: PAN,
      PAYMENT_ENDPOINT: 'https://api.example.com',
    });

    expect(built.apiToken).toBeInstanceOf(SensitiveString);
    expect(String(built.apiToken)).toBe('[REDACTED:credential]');
  });
});
