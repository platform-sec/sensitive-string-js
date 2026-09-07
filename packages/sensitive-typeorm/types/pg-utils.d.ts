/**
 * Ambient typings for the one `pg` internal the driver-bypass suite calls.
 *
 * `prepareValue` is what decides how a bound parameter reaches the wire, and it
 * is the function that turns a `SensitiveString` into a quoted redaction
 * marker. It is not on `pg`'s public entry point and `@types/pg` does not
 * declare the subpath, so the suite declares just the one signature it uses
 * rather than casting the import to `any`. Same reason the Express 4 alias has
 * its own typings directory.
 */
declare module 'pg/lib/utils.js' {
  export function prepareValue(value: unknown): unknown;
  const utils: { prepareValue: typeof prepareValue };
  export default utils;
}
