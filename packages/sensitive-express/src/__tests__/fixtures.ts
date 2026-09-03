import type { SensitiveString } from '@platform-sec/sensitive-string-core';
import express, {
  type ErrorRequestHandler,
  type Express,
  type Request,
  type RequestHandler,
} from 'express';

/**
 * The canary every leak assertion looks for. One constant, so a test that
 * forgets to assert absence is visible next to one that does not.
 */
export const CANARY = 'LEAKED_SECRET_abc123xyz';

/** A second canary, for a test that needs two distinguishable values. */
export const OTHER_CANARY = 'LEAKED_SECRET_def456uvw';

export interface TestApp {
  app: Express;
  /** Errors that reached the terminal error handler, in arrival order. */
  errors: unknown[];
}

/**
 * Build an Express application with a terminal error handler that records what
 * reached it.
 *
 * The recorder matters for the parse-error tests, which have to inspect the
 * error object itself rather than the status the client sees. It is registered
 * last, after `configure` has added everything else, which is the position
 * Express requires of an error handler.
 */
export function createTestApp(configure: (app: Express) => void): TestApp {
  const app = express();
  const errors: unknown[] = [];

  configure(app);

  const terminal: ErrorRequestHandler = (err, _req, res, _next) => {
    errors.push(err);

    const status = statusOf(err);

    res.status(status).json({ error: 'handled' });
  };

  app.use(terminal);

  return { app, errors };
}

function statusOf(err: unknown): number {
  if (err !== null && typeof err === 'object' && 'status' in err) {
    const status = (err as { status?: unknown }).status;

    if (typeof status === 'number' && status >= 400 && status <= 599) {
      return status;
    }
  }

  return 500;
}

/**
 * Record whatever a handler saw, for assertion after the request resolves.
 *
 * An `expect` that throws inside a handler becomes a 500, and the request
 * expectation then reports the wrong status rather than the real failure. Every
 * suite here captures instead, and asserts once supertest has returned.
 */
export function capture<T>(): { set(value: T): void; get(): T } {
  let held: T | undefined;
  let assigned = false;

  return {
    set(value: T) {
      held = value;
      assigned = true;
    },
    get(): T {
      if (!assigned) {
        throw new Error('capture() was never set: the handler did not run');
      }

      return held as T;
    },
  };
}

/**
 * Replace `res.json` before another middleware wraps it, so a test can see the
 * body that middleware produced.
 *
 * Registered *before* `sensitiveResponseFilter()`, this becomes the function
 * the filter binds and calls, which is the only place the redacted copy is
 * observable as an object rather than as response text.
 */
export function captureJsonBody(sink: { set(value: unknown): void }): RequestHandler {
  return (_req, res, next) => {
    const original = res.json.bind(res) as (body?: unknown) => unknown;

    res.json = ((body?: unknown) => {
      sink.set(body);

      return original(body);
    }) as typeof res.json;

    next();
  };
}

/**
 * `req.body` as an inspectable record.
 *
 * Express types the property `any`, which the type-aware lint rules refuse to
 * let a test read through. One cast here beats one per assertion.
 */
export function bodyOf(req: Request): Record<string, unknown> {
  return req.body as Record<string, unknown>;
}

/** Stands in for an ORM entity: a class instance, not a plain object. */
export class UserEntity {
  constructor(
    readonly id: number,
    readonly email: SensitiveString<'sensitive'>,
    readonly apiKey: SensitiveString<'credential'>
  ) {}
}

/** An entity that decides its own serialized shape. */
export class ProfileEntity {
  constructor(
    readonly id: number,
    readonly email: SensitiveString<'sensitive'>
  ) {}

  toJSON() {
    return { kind: 'profile', id: this.id, email: this.email };
  }
}
