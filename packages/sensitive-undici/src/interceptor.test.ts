import { describe, expect, it, vi } from 'vitest';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { MarkerLeakError } from '@platform-sec/sensitive-string-http';
import type { Dispatcher } from 'undici';

import { markerGuard } from './interceptor.js';

/**
 * The interceptor, driven directly rather than through a live dispatcher.
 *
 * It cannot reveal: by the time a dispatch reaches it the caller has already
 * produced strings. What it can do is refuse, and these assert exactly which
 * positions it reads.
 */

const CANARY = 'LEAKED_SECRET_abc123xyz';
const marker = String(new SensitiveString(CANARY, 'credential'));

function guarded(options: { base64?: boolean } = {}) {
  const dispatch = vi.fn(() => true) as unknown as Dispatcher['dispatch'];
  const wrapped = markerGuard(options)(dispatch);
  const handler = {} as Dispatcher.DispatchHandler;

  return {
    dispatch,
    send: (opts: Partial<Dispatcher.DispatchOptions>) =>
      wrapped({ path: '/x', method: 'GET', ...opts }, handler),
  };
}

describe('markerGuard', () => {
  it('passes a clean dispatch straight through', () => {
    const { dispatch, send } = guarded();

    expect(send({ headers: { 'x-api-key': 'sk_live_real' }, body: '{"a":1}' })).toBe(true);
    expect(dispatch).toHaveBeenCalledTimes(1);
  });

  it('refuses a marker in a record-shaped header bag, naming the header', () => {
    const { dispatch, send } = guarded();

    expect(() => send({ headers: { 'x-api-key': marker } })).toThrow(/header 'x-api-key'/);
    expect(dispatch).not.toHaveBeenCalled();
  });

  it("refuses a marker in undici's flat header array form", () => {
    const { send } = guarded();

    expect(() => send({ headers: ['x-trace', 'abc', 'x-api-key', marker] })).toThrow(
      MarkerLeakError
    );
  });

  it('refuses a percent-encoded marker in the request path', () => {
    const { send } = guarded();

    expect(() => send({ path: `/x?token=${encodeURIComponent(marker)}` })).toThrow(/request path/);
  });

  it('refuses a marker in a string body and in a Uint8Array body', () => {
    const { send } = guarded();

    expect(() => send({ body: `{"token":"${marker}"}` })).toThrow(/request body/);
    expect(() => send({ body: Buffer.from(marker) })).toThrow(/request body/);
  });

  it('ignores a body shape it cannot read, rather than guessing', () => {
    const { dispatch, send } = guarded();

    expect(send({ body: { stream: true } as never })).toBe(true);
    expect(dispatch).toHaveBeenCalledTimes(1);
  });

  it('ignores a non-string header value and a missing header bag', () => {
    const { dispatch, send } = guarded();

    expect(send({ headers: { 'content-length': 12 } as never })).toBe(true);
    expect(send({})).toBe(true);
    expect(dispatch).toHaveBeenCalledTimes(2);
  });

  it('finds a base64-hidden marker only when asked', () => {
    const encoded = Buffer.from(`user:${marker}`).toString('base64');

    expect(guarded().send({ headers: { authorization: `Basic ${encoded}` } })).toBe(true);
    expect(() =>
      guarded({ base64: true }).send({ headers: { authorization: `Basic ${encoded}` } })
    ).toThrow(MarkerLeakError);
  });
});
