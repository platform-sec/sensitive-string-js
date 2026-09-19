import type {
  DestinationBinding,
  RevealContext,
  SensitiveStringOptions,
  SerializedDestinationBinding,
} from './types.js';
import { SensitiveStringError } from './errors.js';

/**
 * Destination binding: a value says where it may go, and the gate checks the
 * reveal context against it.
 *
 * Every other control in the gate answers a question about the value or about
 * the process: is it expired, is it revoked, is this region allowed to read
 * it, has its budget been spent. None of them asks where the plaintext is
 * about to be sent. So a credential can be wrapped at entry, revealed at
 * exactly the call site the design says to reveal it, audited, and still
 * written to the wrong host, because the reveal authorized a call site and not
 * a recipient. Measured seven times in the adoption corpus, twice as the same
 * substring host comparison written by two unrelated maintainers.
 *
 * This module is the recipient half. A value constructed with `destinations`
 * carries the sinks and the hosts it may be revealed toward, and every
 * exposing read is checked against the `sink` and `host` tags of the context
 * it runs under. Those two tags are the ones the integrations already write:
 * the HTTP clients set `tags.sink: 'http'` and `tags.host` from the request
 * URL on every reveal, the data layer sets `tags.sink` to its driver, and the
 * LLM package sets it to the sink name it was given. A context that states no
 * destination is refused, on the rule the environment restrictions already
 * follow: an allowlist is the statement "only here", and a caller who has not
 * said where the value is going has not shown that it is going there.
 *
 * What it protects against is what every gate check here protects against: a
 * program that computed its request URL from the wrong input, a credential
 * store that answered a lookup for the wrong origin, a comparison that let
 * `registry.example.com.attacker.net` pass for `registry.example.com`. It does
 * not protect against code in the process that writes the tag itself, which
 * is inside the stated threat model and also visible in the audit record it
 * would have to lie in.
 */

/** Which half of a binding refused. */
export type DestinationKind = 'sink' | 'host';

/**
 * Raised when an operation needs the raw value of an instance the current
 * context's destination is not allowed to receive.
 *
 * `restriction` says which tag refused and `currentValue` is what the context
 * stated for it, or `undefined` when the context stated nothing. All of it is
 * configuration and none of it is any part of the protected value, so the
 * message is safe to log.
 */
export class DestinationRestrictedError extends SensitiveStringError {
  override readonly name = 'DestinationRestrictedError';
  override readonly code = 'destination-restricted';

  constructor(
    readonly restriction: DestinationKind,
    readonly currentValue: string | undefined,
    readonly allowedValues: readonly string[],
    readonly label?: string
  ) {
    const named = label !== undefined ? ` '${label}'` : '';
    const allowed = allowedValues.join(', ');

    super(
      `Sensitive value${named} cannot be revealed toward this destination: ` +
        (currentValue === undefined
          ? `the reveal context states no ${restriction} tag, and the value may only go to ` +
            `${restriction} ${allowed}. Reveal it under a context whose tags name the ` +
            `${restriction}, which the HTTP, data and LLM integrations do on every reveal.`
          : `${restriction} is '${currentValue}', and the value may only go to ${restriction} ` +
            `${allowed}`)
    );
  }
}

/** Describe a rejected option without disclosing it. */
function describeType(value: unknown): string {
  return value === null ? 'null' : typeof value;
}

/**
 * A validated binding, held by the value that declares it.
 *
 * Lists are copied out of the caller's object, for the reason the environment
 * restrictions copy theirs: they are read on every access, and a caller who
 * mutates the array they passed must not be able to widen a binding after the
 * fact. Hosts are stored lowercased, which is the form they are compared in.
 */
export interface ResolvedDestination {
  readonly sinks: readonly string[] | undefined;
  readonly hosts: readonly string[] | undefined;
}

/** The shared empty array a value with no binding points at. */
export const NO_DESTINATIONS: readonly ResolvedDestination[] = Object.freeze([]);

/** The two fields, in the order they are checked and serialized. */
const LIST_FIELDS = ['sinks', 'hosts'] as const;

/**
 * Characters that cannot appear in a host entry because they belong to some
 * other part of a URL. A scheme, a path, a query, a fragment or a userinfo
 * pasted into a host list would never equal a `host` tag, so the entry would
 * sit in the list matching nothing, which is the shape of the defect this
 * feature exists to catch rather than reproduce.
 */
const NOT_A_HOST = /[\s/?#@\\]/;

function requireList(value: unknown, name: (typeof LIST_FIELDS)[number]): readonly string[] {
  if (!Array.isArray(value)) {
    throw new TypeError(
      `SensitiveString: destinations.${name} must be an array of strings, received ${describeType(value)}`
    );
  }

  if (value.length === 0) {
    throw new RangeError(
      `SensitiveString: destinations.${name} is empty. An empty list expresses no binding and ` +
        'would silently allow everything; omit the field instead.'
    );
  }

  return Object.freeze(
    value.map((entry: unknown, index) => {
      if (typeof entry !== 'string') {
        throw new TypeError(
          `SensitiveString: destinations.${name}[${index}] must be a string, received ${describeType(entry)}`
        );
      }

      if (entry === '') {
        throw new RangeError(`SensitiveString: destinations.${name}[${index}] must not be empty`);
      }

      return name === 'hosts' ? requireHost(entry, index) : requireSink(entry, index);
    })
  );
}

/**
 * A sink name is matched literally and carries no wildcard: the integrations
 * that write the tag write a fixed name, and a pattern over `'http'`,
 * `'prisma'` or `'anthropic'` has nothing to abbreviate.
 */
function requireSink(entry: string, index: number): string {
  if (entry.includes('*') || /\s/.test(entry)) {
    throw new RangeError(
      `SensitiveString: destinations.sinks[${index}] must be a literal sink name with no ` +
        "wildcard or whitespace, such as 'http' or 'anthropic'."
    );
  }

  return entry;
}

/**
 * A host entry is what `new URL(...).host` spells: a lowercase hostname, with
 * the port when it is not the scheme's default, or `*.` followed by a domain,
 * which matches every host at least one label below it and not the domain
 * itself.
 *
 * Nothing more is normalized. A trailing dot, a punycode form and a stated
 * default port are all different strings from their equivalents, and an entry
 * that does not equal what the integration writes refuses rather than passes,
 * which is the direction to fail in. Case is the exception: DNS names are
 * case-insensitive and a hand-written tag may not be lowercase.
 */
function requireHost(entry: string, index: number): string {
  const host = entry.toLowerCase();

  if (NOT_A_HOST.test(host) || host.includes('://')) {
    throw new RangeError(
      `SensitiveString: destinations.hosts[${index}] must be a host, not a URL: no scheme, ` +
        'path, query, fragment, userinfo or whitespace. Write what `new URL(url).host` returns, ' +
        "such as 'api.example.com' or 'api.example.com:8443'."
    );
  }

  const star = host.indexOf('*');

  if (star !== -1) {
    // A leading `*.` and nothing else: '*.example.com' matches every host
    // below example.com. 'api.*.com', 'api.example.*' and a bare '*' are
    // refused rather than matched as literals, which would leave the list
    // matching nothing, or in the bare case read as "anywhere", which this
    // option exists to stop a value from being.
    if (star !== 0 || host.length < 3 || host[1] !== '.' || host.includes('*', 1)) {
      throw new RangeError(
        `SensitiveString: destinations.hosts[${index}] may only carry '*' as a leading '*.' ` +
          "prefix, such as '*.example.com'. A bare '*' would bind the value to nowhere in " +
          'particular, which is what omitting the option already means.'
      );
    }
  }

  // The rest must be a host the URL parser would hand back unchanged under
  // either scheme. That is what refuses the entries the character check
  // cannot see: a Unicode domain the parser would have written in punycode, a
  // full-width stop it would have mapped to a dot, a bare port, and a stated
  // default port, `:443` or `:80`, which `URL.host` elides and a tag would
  // therefore never carry. Each would sit in the list matching nothing.
  const literal = star === 0 ? host.slice(2) : host;

  if (!isCanonicalHost(literal)) {
    throw new RangeError(
      `SensitiveString: destinations.hosts[${index}] is not spelled as \`new URL(url).host\` ` +
        'would spell it: write the lowercase hostname in its punycode form, with the port only ' +
        'when it is not the default for the scheme.'
    );
  }

  return host;
}

/** Whether the URL parser hands this host back unchanged under `http:` and `https:`. */
function isCanonicalHost(host: string): boolean {
  try {
    return new URL(`http://${host}/`).host === host && new URL(`https://${host}/`).host === host;
  } catch {
    return false;
  }
}

function resolveOne(binding: DestinationBinding, index: number): ResolvedDestination {
  if (typeof binding !== 'object' || binding === null || Array.isArray(binding)) {
    throw new TypeError(
      `SensitiveString: destinations[${index}] must be an object, received ` +
        `${Array.isArray(binding) ? 'an array' : describeType(binding)}`
    );
  }

  const lists: { sinks?: readonly string[]; hosts?: readonly string[] } = {};
  let declared = false;

  for (const field of LIST_FIELDS) {
    const value = binding[field];

    if (value !== undefined) {
      lists[field] = requireList(value, field);
      declared = true;
    }
  }

  if (!declared) {
    // A binding that binds to nothing is configuration that was meant to do
    // something. Refusing it here is the same choice the empty list makes,
    // for the same reason.
    throw new Error(
      'SensitiveString: destinations declares no destination. Give it sinks, hosts or both, ' +
        'or omit the option.'
    );
  }

  return { sinks: lists.sinks, hosts: lists.hosts };
}

/**
 * Build the destination state for a newly constructed value.
 *
 * Every list is validated here, at construction, so a URL pasted where a host
 * belongs is rejected at the call that wrote it rather than refusing every
 * reveal months later.
 *
 * The option accepts a list as well as a single binding, because a value
 * derived from two bound values carries both, and the wire format has to be
 * able to carry them back.
 *
 * @throws TypeError If an option has the wrong type.
 * @throws RangeError If a list is empty or an entry is not a host or a sink.
 * @throws Error If a binding names no destination.
 */
export function planDestinations(
  options: SensitiveStringOptions | undefined
): readonly ResolvedDestination[] | undefined {
  const declared = options?.destinations;

  if (declared === undefined) {
    return undefined;
  }

  const bindings = Array.isArray(declared)
    ? (declared as readonly DestinationBinding[])
    : [declared as DestinationBinding];

  if (bindings.length === 0) {
    throw new RangeError(
      'SensitiveString: destinations is an empty list, which binds the value to nothing; ' +
        'omit the option instead.'
    );
  }

  return Object.freeze(bindings.map(resolveOne));
}

/**
 * Whether a host matches one entry.
 *
 * `*.example.com` matches `api.example.com` and `a.b.example.com`, and does
 * not match `example.com`: the wildcard stands for at least one label. A port
 * is part of the suffix, so `*.example.com` does not match
 * `api.example.com:8443` and `*.example.com:8443` does. Any other entry is
 * equality. Both sides are already lowercase.
 */
function matchesHost(host: string, entry: string): boolean {
  if (entry.startsWith('*.')) {
    const suffix = entry.slice(1);

    return host.length > suffix.length && host.endsWith(suffix);
  }

  return host === entry;
}

function matchesAnyHost(host: string, entries: readonly string[]): boolean {
  for (const entry of entries) {
    if (matchesHost(host, entry)) {
      return true;
    }
  }

  return false;
}

/**
 * The tag a context states for a destination field, or `undefined` when it
 * states none or states something that is not a string.
 *
 * A non-string is read as absent rather than coerced: a tag written as a URL
 * object or a number is a context that did not say what this check reads, and
 * `String(url)` would compare a whole URL against a host and refuse anyway,
 * with a less useful message.
 */
function statedTag(
  ctx: RevealContext | null | undefined,
  name: DestinationKind
): string | undefined {
  const tag = ctx?.tags?.[name];

  return typeof tag === 'string' ? tag : undefined;
}

/**
 * Refuse the read unless the context's destination satisfies every binding.
 *
 * Every binding has to pass, so a value derived from two bound values is at
 * least as bound as each of them, which is rule R2's combination rule with
 * nothing to decide: an intersection is what sharing the state already gives.
 *
 * A context that states no `sink` or no `host` refuses a binding on that
 * field. This is the allowlist rule the environment restrictions follow, and
 * it is the whole point here: a reveal that does not say where the value is
 * going is the reveal this feature exists to refuse.
 *
 * @throws DestinationRestrictedError If any binding refuses.
 */
export function checkDestinations(
  destinations: readonly ResolvedDestination[],
  ctx: RevealContext | null | undefined,
  label: string | undefined
): void {
  const sink = statedTag(ctx, 'sink');
  const host = statedTag(ctx, 'host')?.toLowerCase();

  for (const binding of destinations) {
    if (binding.sinks !== undefined && (sink === undefined || !binding.sinks.includes(sink))) {
      throw new DestinationRestrictedError('sink', sink, binding.sinks, label);
    }

    if (
      binding.hosts !== undefined &&
      (host === undefined || !matchesAnyHost(host, binding.hosts))
    ) {
      throw new DestinationRestrictedError('host', host, binding.hosts, label);
    }
  }
}

/**
 * The wire form of these bindings. Lists only, so nothing is dropped.
 */
export function serializeDestinations(
  destinations: readonly ResolvedDestination[]
): SerializedDestinationBinding[] {
  return destinations.map((binding) => {
    const wire: SerializedDestinationBinding = {};

    for (const field of LIST_FIELDS) {
      const list = binding[field];

      if (list !== undefined) {
        wire[field] = [...list];
      }
    }

    return wire;
  });
}

/**
 * Read bindings out of an untrusted payload.
 *
 * They can only tighten: a value rebuilt by `deserialize()` starts with none,
 * so anything a payload carries here refuses reads that would otherwise have
 * been allowed, and there is no spelling of "no binding" that lifts one.
 *
 * An unknown key is rejected rather than ignored, for the reason the
 * environment restrictions reject one: a sender describing a limit this
 * receiver does not know would have that limit silently unenforced.
 */
export function deserializeDestinations(
  serialized: object
): readonly DestinationBinding[] | undefined {
  if (!('destinations' in serialized) || serialized.destinations === undefined) {
    return undefined;
  }

  const declared: unknown = serialized.destinations;

  if (!Array.isArray(declared)) {
    throw new Error('Invalid SerializedSensitiveString: destinations must be an array');
  }

  if (declared.length === 0) {
    throw new Error(
      'Invalid SerializedSensitiveString: destinations is empty. A payload that binds nothing ' +
        'omits the field rather than carrying an empty list.'
    );
  }

  return declared.map((entry: unknown, index): DestinationBinding => {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
      throw new Error(
        `Invalid SerializedSensitiveString: destinations[${index}] must be an object`
      );
    }

    const binding: DestinationBinding = {};

    for (const key of Object.keys(entry)) {
      if (!(LIST_FIELDS as readonly string[]).includes(key)) {
        throw new Error(
          `Invalid SerializedSensitiveString: destinations[${index}] carries unknown key '${key}'. ` +
            'A binding this receiver cannot enforce is refused rather than ignored.'
        );
      }

      (binding as Record<string, unknown>)[key] = (entry as Record<string, unknown>)[key];
    }

    // The lists themselves are validated by `planDestinations`, which is the
    // same check a locally constructed value gets, so a payload cannot smuggle
    // an entry shape the constructor would have refused.
    return binding;
  });
}
