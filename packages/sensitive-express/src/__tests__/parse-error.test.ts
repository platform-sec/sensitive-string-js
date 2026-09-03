import type { Request, Response } from 'express';
import { describe, expect, it, vi } from 'vitest';
import { stripParseErrorBody } from '../parse-error.js';
import { CANARY } from './fixtures.js';

/**
 * Unit tests for the shapes an error can take that no HTTP request produces.
 *
 * body-parser's own error is an ordinary object with a configurable `body`
 * property, which `security.test.ts` covers end to end. What is checked here is
 * that a property the middleware cannot delete still does not stop the error
 * from travelling on: an error swallowed inside an error handler is a worse
 * outcome than the leak the middleware is trying to close.
 */
describe('stripParseErrorBody', () => {
  const run = (err: unknown): { next: ReturnType<typeof vi.fn> } => {
    const next = vi.fn();

    stripParseErrorBody()(err, {} as Request, {} as Response, next);

    return { next };
  };

  it('deletes a plain body property', () => {
    const err = Object.assign(new Error('bad json'), { body: CANARY, status: 400 });

    const { next } = run(err);

    expect('body' in err).toBe(false);
    expect(err.status).toBe(400);
    expect(next).toHaveBeenCalledWith(err);
  });

  it('overwrites a body property that cannot be deleted', () => {
    const err = new Error('bad json');

    Object.defineProperty(err, 'body', { value: CANARY, configurable: false, writable: true });

    const { next } = run(err);

    expect((err as unknown as { body: unknown }).body).toBeUndefined();
    expect(next).toHaveBeenCalledWith(err);
  });

  it('passes on an error whose body can neither be deleted nor overwritten', () => {
    const err = new Error('bad json');

    Object.defineProperty(err, 'body', { value: CANARY, configurable: false, writable: false });

    const { next } = run(err);

    // The value is unreachable from here. Reporting that honestly means letting
    // the error through rather than throwing a TypeError over it.
    expect((err as unknown as { body: unknown }).body).toBe(CANARY);
    expect(next).toHaveBeenCalledWith(err);
  });

  it('passes on a non-object error unchanged', () => {
    const { next } = run('a string thrown as an error');

    expect(next).toHaveBeenCalledWith('a string thrown as an error');
  });

  it('passes on null unchanged', () => {
    const { next } = run(null);

    expect(next).toHaveBeenCalledWith(null);
  });
});
