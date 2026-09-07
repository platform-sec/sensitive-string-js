import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  SensitiveString,
  UnauditedWorkerError,
  withRevealContext,
} from '@platform-sec/sensitive-string-core';
import type { RevealDetails } from '@platform-sec/sensitive-string-core';

import { SIGNER_FILE, signBatch, signerPayload } from './worker-handoff.js';

/**
 * Both halves in one process, with `structuredClone` standing in for the
 * thread boundary. Core's own suite drives a real `Worker`; what this pins is
 * the shape of the example, which is what a reader will copy.
 */

const KEY = 'LEAKED_KEY_abc123xyz';

describe('worker handoff example', () => {
  it('signs the batch in the worker, under the carried context, and records both sides', () => {
    const sent: RevealDetails[] = [];
    const received: RevealDetails[] = [];
    const batch = { documents: ['invoice-1', 'invoice-2'] };

    const payload = withRevealContext(
      {
        name: 'signing-request',
        reason: 'nightly batch',
        auditReveal: (_value, details) => {
          sent.push(details);
        },
      },
      () => signerPayload(new SensitiveString(KEY, 'credential', 'signing_key'), batch)
    );
    const crossed = structuredClone(payload);

    const signatures = signBatch(crossed, (_value, details) => {
      received.push(details);
    });

    expect(signatures).toEqual(
      batch.documents.map((document) => createHmac('sha256', KEY).update(document).digest('hex'))
    );
    expect(sent).toEqual([
      {
        operation: 'worker-handoff',
        worker: SIGNER_FILE,
        key: 'signingKey',
        auditHookDropped: true,
      },
    ]);
    expect(received).toEqual([{ operation: 'reveal' }]);

    // The payload the worker was started with no longer holds the key.
    expect(JSON.stringify(crossed)).not.toContain(KEY);
    expect(crossed.consumed).toBe(true);
  });

  it('refuses to sign without a hook when the sender had one', () => {
    const payload = signerPayload(
      new SensitiveString(KEY, 'credential', 'signing_key'),
      { documents: [] },
      { name: 'signing-request', auditReveal: () => undefined }
    );

    expect(() => signBatch(structuredClone(payload), undefined as unknown as () => void)).toThrow(
      UnauditedWorkerError
    );
  });
});
