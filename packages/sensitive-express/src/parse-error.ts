import type { ErrorRequestHandler } from 'express';

/**
 * Remove the raw request body that body-parser attaches to a parse error.
 *
 * When `express.json()` cannot parse a body it raises a 400 and puts the
 * unparsed text on the error as `err.body`, so a login request with a stray
 * comma leaves the password on an object that is about to reach an error
 * handler, a logger, and whatever ships logs onward. Nothing has wrapped
 * anything at that point: the failure happened before any field map could
 * apply, which is why this is the one piece of the package that has to run
 * directly after the parser.
 *
 * The error itself is passed on unchanged otherwise, so the application's own
 * error handler still sees the status, the type, and the message body-parser
 * set.
 *
 * @returns Express error-handling middleware
 *
 * @example
 * ```ts
 * app.use(express.json());
 * app.use(stripParseErrorBody());
 * ```
 */
export function stripParseErrorBody(): ErrorRequestHandler {
  return (err: unknown, _req, _res, next) => {
    const target: object | null = typeof err === 'object' ? err : null;

    if (target !== null && 'body' in target) {
      // Reflect rather than `delete`, which throws in strict mode on a
      // non-configurable property. Losing the error to a TypeError raised
      // inside an error handler would be a worse outcome than the leak.
      if (!Reflect.deleteProperty(target, 'body')) {
        try {
          (target as { body?: unknown }).body = undefined;
        } catch {
          // Frozen error object. The property is unreachable from here; the
          // error still travels on, which is better than swallowing it.
        }
      }
    }

    next(err);
  };
}
