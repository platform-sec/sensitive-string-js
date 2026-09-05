import {
  assertKeyedDerivationOptions,
  createChildContext,
  deriveKeyedToken,
  SensitiveString,
  type SensitivityClass,
} from '@platform-sec/sensitive-string-core';

import type { EntityHandleOptions, HandleMap } from './types.js';

/**
 * Entity handles: a stable pseudonym a model can reason about.
 *
 * A handle lets a model be told "the customer" and carry that reference across
 * turns without receiving the customer. It is worth having and it is worth
 * being precise about what it is: a pseudonym, not anonymization. Stability is
 * the feature, and a stable token is a correlation key. Whoever holds the
 * conversation logs can count how often the same entity appears, which
 * entities co-occur, and what was said about each; under one key and scope
 * that holds across every conversation the application ever sends. `scope` is
 * the control for that, which is why the guidance is to scope per
 * conversation.
 *
 * A handle also discloses that an entity of that kind existed, and the prefix
 * says which kind. That is the point, and it is still disclosure.
 */

/**
 * The token shape.
 *
 * Delimiters a model is unlikely to produce by accident, a prefix naming the
 * kind, and a hex body. Recognizing a handle is a syntactic test, which is
 * exactly why the extractor is not an authorization: forging one costs
 * nothing, and `rehydrate` resolves against a per-call map rather than against
 * this pattern.
 */
const PREFIX_PATTERN = /^[A-Za-z0-9_-]{1,32}$/;
const HANDLE_SOURCE = '<<([A-Za-z0-9_-]{1,32}):([0-9a-f]{12,64})>>';

/** The default prefix, for a value with no usable label. */
const DEFAULT_PREFIX = 'E';

/**
 * A fresh global matcher for the handle shape.
 *
 * Fresh per call rather than a module constant. A global `RegExp` carries
 * `lastIndex` between calls, and a shared one would make a second scan of the
 * same text answer differently from the first: the bug `core` fixed by
 * stripping the `g` flag from caller-supplied classification patterns.
 */
export function handlePattern(): RegExp {
  return new RegExp(HANDLE_SOURCE, 'g');
}

/** Raised when a value's class may not be pseudonymized. */
export class HandleNotAllowedError extends Error {
  readonly klass: SensitivityClass;

  constructor(klass: SensitivityClass) {
    super(
      klass === 'credential'
        ? 'entityHandle: a credential does not get a handle. A model that needs a key needs the ' +
            'key, and a model that does not need the key should not be told a key exists.'
        : `entityHandle: handles are minted for the 'sensitive' class only, not '${klass}'`
    );
    this.name = 'HandleNotAllowedError';
    this.klass = klass;
  }
}

/**
 * A fresh, empty reverse map for one request.
 *
 * Exported as a constructor rather than held as module state, so the package
 * keeps no mutable state of its own and a caller cannot accidentally share one
 * map between two users.
 */
export function createHandleMap(): HandleMap {
  return new Map();
}

/**
 * Mint a stable, keyed pseudonym for a value.
 *
 * `HMAC-SHA256(key, scope || 0x00 || klass || 0x00 || value)`, hex, truncated,
 * wrapped in the token delimiters. Keyed, never a plain hash: the values that
 * get handles are low-entropy by definition, an email address under an unkeyed
 * SHA-256 is recoverable from a wordlist in seconds, and the entire premise of
 * a handle is that it appears in a payload sent outside the trust boundary,
 * which is exactly where an offline attack happens.
 *
 * The class is in the derivation input alongside the scope, so the same string
 * classified two ways gets two handles. Reclassification is an audited
 * operation and a handle that survived it would be a channel around the audit.
 *
 * This is a reveal. It reads the value, so it runs the ordinary gate and
 * produces an audit record, under a context named `handle:<scope>` rather than
 * `external:<sink>`. A handle is not a transmission, so it does not run the
 * `allowSendToExternal` check, and an audit sink that wants to tell the two
 * apart has the name prefix to do it with.
 *
 * Refused for `credential`, and for any class other than `sensitive`. The
 * refusal is hard-coded rather than read from a policy flag: `allowMask` and
 * `allowPartialQueries` are both false on `credential` by default, which is
 * the same question asked about a different derived form, and overloading
 * either of them would make one flag mean two things. A test asserts the
 * refusal stays hard-coded.
 *
 * @param value - The value to pseudonymize
 * @param options - The key, the scope, the token length, the prefix, and an
 *                  optional per-request map to record the handle in
 * @returns The token, `<<prefix:hex>>`
 *
 * @throws TypeError If the value is not a `SensitiveString`, or an explicit
 *         prefix is not `[A-Za-z0-9_-]{1,32}`.
 * @throws HandleNotAllowedError If the value's class is not `sensitive`.
 * @throws RangeError If the key is too short or the length is out of bounds.
 *
 * @example
 * ```ts
 * const map = createHandleMap();
 * const handle = entityHandle(customerEmail, {
 *   key: process.env.HANDLE_KEY_BYTES,
 *   scope: conversationId,
 *   record: map,
 * });
 *
 * const prompt = `Draft a refund note to ${handle}.`;
 * ```
 */
export function entityHandle(
  value: SensitiveString<SensitivityClass>,
  options: EntityHandleOptions
): string {
  if (!(value instanceof SensitiveString)) {
    throw new TypeError('entityHandle: value must be a SensitiveString');
  }

  if (value.klass !== 'sensitive') {
    throw new HandleNotAllowedError(value.klass);
  }

  if (options === null || typeof options !== 'object') {
    throw new TypeError('entityHandle: options must carry at least a key');
  }

  const prefix = resolvePrefix(options.prefix, value.label);
  const scope = options.scope ?? '';

  if (typeof scope !== 'string') {
    throw new TypeError('entityHandle: options.scope must be a string');
  }

  const derivation = {
    key: options.key,
    // Scope first, then class, then the value. The class is a domain component
    // rather than part of the scope so a caller cannot collide the two by
    // naming a scope after a class.
    domain: [scope, value.klass],
    ...(options.length === undefined ? {} : { length: options.length }),
  };

  // Everything that can be decided without the value is decided before the
  // value is read. A key below the entropy floor or a length below the
  // collision floor is a caller's typo, and settling it after the reveal would
  // leave an audit record for a read that produced nothing, which is the same
  // rule core's raw-value gate applies to a denied read.
  assertKeyedDerivationOptions(derivation);

  const raw = value.reveal(
    createChildContext({
      name: scope === '' ? 'handle' : `handle:${scope}`,
      reason: 'deriving an entity handle for a model prompt',
      tags: { handleScope: scope, handlePrefix: prefix },
    })
  );

  const digest = deriveKeyedToken(raw, derivation);

  const token = `<<${prefix}:${digest}>>`;

  options.record?.set(token, value);

  return token;
}

/**
 * The prefix for a token.
 *
 * An explicit prefix outside the allowed set is an error, because a caller who
 * asked for one and silently got `E` would find out from a rehydration that
 * matched nothing. A label outside the set falls back instead: a label is
 * chosen for audit categorization rather than for this, and refusing a value
 * because its label has a space in it would be a surprising place to fail.
 */
function resolvePrefix(explicit: string | undefined, label: string | undefined): string {
  if (explicit !== undefined) {
    if (typeof explicit !== 'string' || !PREFIX_PATTERN.test(explicit)) {
      throw new TypeError(
        'entityHandle: options.prefix must match [A-Za-z0-9_-]{1,32}, so the token stays parseable'
      );
    }

    return explicit;
  }

  return label !== undefined && PREFIX_PATTERN.test(label) ? label : DEFAULT_PREFIX;
}
