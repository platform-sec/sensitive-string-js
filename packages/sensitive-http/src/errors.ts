/**
 * The errors these packages throw.
 *
 * Every one of them is a refusal, and a refusal has to explain itself without
 * becoming the disclosure it prevented. So none of these carries a value: they
 * carry a path, a header name, a host, a class, a byte length, a content type.
 * The one place that rule is easy to break is the response decoder, which is
 * handed a body that failed to parse and would name it in the obvious message.
 * `ResponseDecodeError` is the reason this module exists as its own file.
 */

/** Base class, so an application can catch everything these packages throw. */
export class SensitiveHttpError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/**
 * A redaction marker was found in an outgoing representation.
 *
 * This is failure mode 1: the value was never revealed and the request would
 * have carried `[REDACTED:credential]` to the server, which answers 401 and
 * tells nobody why.
 */
export class MarkerLeakError extends SensitiveHttpError {
  constructor(
    /** Where the marker was found, e.g. `request body` or `header 'x-api-key'`. */
    readonly where: string,
    /** Which encoding the scan found it in. */
    readonly encoding: 'literal' | 'percent' | 'base64'
  ) {
    super(
      `Refusing to send: ${where} contains a redaction marker (${encoding} encoding). ` +
        `A SensitiveString was stringified rather than revealed, most often by template ` +
        `interpolation such as \`Bearer \${token}\`, by JSON.stringify, or by putting an ` +
        `instance into a Headers, URLSearchParams or FormData, all of which stringify on ` +
        `construction. Pass the instance itself, or build the header with bearer(), ` +
        `basic() or apiKey().`
    );
  }
}

/**
 * A request body held a container a JSON body cannot represent.
 *
 * axios turns a `Map` in a JSON body into `{}` and drops the field. Nothing
 * throws and nothing is logged, so the caller learns about it from the server.
 * The walker refuses instead.
 */
export class UnserializableBodyError extends SensitiveHttpError {
  constructor(
    /** Dot path of the offending value in the request body. */
    readonly path: string,
    /** Constructor name of the offending value. */
    readonly kind: string
  ) {
    super(
      `Refusing to send: ${path === '' ? 'the request body' : `body path '${path}'`} is a ` +
        `${kind}, which a JSON body cannot represent. Serializing it silently produces {} ` +
        `and drops the field. Convert it before the call, for example with ` +
        `Object.fromEntries(map).`
    );
  }
}

/** A redirect pointed at a host the caller never named. */
export class RedirectHostNotAllowedError extends SensitiveHttpError {
  constructor(
    /** The host the server redirected to. */
    readonly host: string,
    /** The hosts the caller allowed, or `false` when redirects are refused outright. */
    readonly allowed: readonly string[] | false,
    /** Which hop refused, counting from 1. */
    readonly hop: number
  ) {
    super(
      allowed === false
        ? `Refusing to follow a redirect to '${host}' at hop ${hop}: this request carries a ` +
            `credential in a header outside the Fetch specification's stripping set ` +
            `(Authorization, Cookie, Proxy-Authorization), and every client measured forwards ` +
            `such a header verbatim across origins. Set allowedHosts to the hosts you trust.`
        : `Refusing to follow a redirect to '${host}' at hop ${hop}: not in allowedHosts ` +
            `[${allowed.join(', ')}].`
    );
  }
}

/** A credential was about to be revealed into a plaintext socket. */
export class InsecureTransportError extends SensitiveHttpError {
  constructor(
    /** The URL whose scheme was rejected, with any query string removed. */
    readonly url: string
  ) {
    super(
      `Refusing to reveal a credential into a plaintext http:// request to '${url}'. ` +
        `Use https://, or set allowInsecureTransport: true if a sidecar or local proxy ` +
        `terminates TLS for you.`
    );
  }
}

/**
 * The redirect budget ran out.
 *
 * Separate from the host refusal because it is a configuration outcome rather
 * than a security one, and a caller distinguishing them wants different code.
 */
export class TooManyRedirectsError extends SensitiveHttpError {
  constructor(readonly limit: number) {
    super(`Refusing to follow more than ${limit} redirects.`);
  }
}

/** Where a decode failed. Carries no body content by construction. */
export interface DecodeSite {
  readonly method: string;
  /** The request URL with its query string removed. */
  readonly url: string;
  /** The response `content-type`, or undefined when the server sent none. */
  readonly contentType: string | undefined;
  /** Byte length of the body that failed to parse. */
  readonly byteLength: number;
}

/**
 * A response body did not parse.
 *
 * `JSON.parse` quotes the first characters of what it choked on, and got
 * appends the full request URL to that message. Measured, a 14-character API
 * key returned with `content-type: application/json` is disclosed whole into an
 * error that `util.inspect` then prints.
 *
 * So this error names the request and the content type, carries the byte
 * length, and carries none of the bytes. The original `SyntaxError` is
 * deliberately **not** chained through `cause`: every reporter that walks a
 * cause chain would put the quoted body back.
 */
export class ResponseDecodeError extends SensitiveHttpError {
  readonly method: string;
  readonly url: string;
  readonly contentType: string | undefined;
  readonly byteLength: number;

  constructor(site: DecodeSite) {
    super(
      `Could not decode the response body of ${site.method} ${site.url} as JSON ` +
        `(content-type: ${site.contentType ?? 'none'}, ${site.byteLength} bytes). ` +
        `The body is not included: a body that is not the JSON you expected is often the ` +
        `credential you sent, echoed back.`
    );
    this.method = site.method;
    this.url = site.url;
    this.contentType = site.contentType;
    this.byteLength = site.byteLength;
  }
}

/**
 * The scrub found a revealed value it could not remove.
 *
 * Thrown on both settlement paths, which on the success path means a 200 is
 * turned into a rejection. That is the one place these packages destroy a
 * working call to keep a guarantee, and it is correct: the alternative is
 * handing back an object that the next `console.log` discloses.
 */
export class SensitiveScrubError extends SensitiveHttpError {
  constructor(
    /** Which client package raised it. */
    readonly client: string,
    /** Property path where the value survived. */
    readonly path: string
  ) {
    super(
      `A revealed value survived the scrub of the ${client} ${path.startsWith('error') ? 'error' : 'response'} ` +
        `at '${path}'. The object is not being returned, because printing it would disclose ` +
        `the value. This is a bug in @platform-sec/sensitive-string-${client}; please report ` +
        `it with the client version.`
    );
  }
}
