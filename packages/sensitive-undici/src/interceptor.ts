import { containsMarker } from '@platform-sec/sensitive-string-http';
import { MarkerLeakError } from '@platform-sec/sensitive-string-http';
import type { Dispatcher } from 'undici';

/**
 * A dispatcher interceptor that refuses to send a marker.
 *
 * For callers who use the dispatcher API directly rather than through
 * `sensitiveRequest`. It cannot reveal: by the time a dispatch reaches an
 * interceptor the caller has already had to produce strings, and the instance
 * that would have been revealed is gone. What it can do is refuse, which is the
 * guarantee that matters most in this direction and the one thing an
 * interceptor is well placed to hold.
 *
 * ```ts
 * import { Agent, setGlobalDispatcher } from 'undici';
 * import { markerGuard } from '@platform-sec/sensitive-string-undici';
 *
 * setGlobalDispatcher(new Agent().compose(markerGuard()));
 * ```
 *
 * undici's own `InvalidArgumentError` names the header and not the value, which
 * is correct behaviour this leaves alone.
 */
export function markerGuard(options: { base64?: boolean } = {}) {
  return (dispatch: Dispatcher['dispatch']): Dispatcher['dispatch'] =>
    function markerGuardDispatch(
      opts: Dispatcher.DispatchOptions,
      handler: Dispatcher.DispatchHandler
    ): boolean {
      assertClean(opts, options.base64 === true);

      return dispatch(opts, handler);
    };
}

function assertClean(opts: Dispatcher.DispatchOptions, base64: boolean): void {
  const scan = { base64, decodeForms: true } as const;
  const headers = opts.headers;

  if (Array.isArray(headers)) {
    // The flat `[name, value, name, value]` form undici also accepts.
    for (let index = 0; index + 1 < headers.length; index += 2) {
      check(headers[index + 1], `header '${String(headers[index])}'`, scan);
    }
  } else if (headers !== null && typeof headers === 'object') {
    for (const [name, value] of Object.entries(headers)) {
      check(value, `header '${name}'`, scan);
    }
  }

  check(opts.path, 'request path', scan);

  if (typeof opts.body === 'string' || opts.body instanceof Uint8Array) {
    check(opts.body, 'request body', scan);
  }
}

function check(
  value: unknown,
  where: string,
  scan: { base64: boolean; decodeForms: boolean }
): void {
  const text =
    typeof value === 'string'
      ? value
      : value instanceof Uint8Array
        ? Buffer.from(value.buffer, value.byteOffset, value.byteLength).toString('utf8')
        : undefined;

  if (text === undefined) {
    return;
  }

  if (containsMarker(text, scan)) {
    throw new MarkerLeakError(where, 'literal');
  }
}
