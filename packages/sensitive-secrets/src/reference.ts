import {
  REFERENCE_VERSION,
  SENSITIVITY_PRECEDENCE,
  carriesReferenceMarker,
  createChildContext,
  hasPolicy,
  isSensitiveValueReference,
  referenceFormatVersion,
  withRevealContext,
} from '@platform-sec/sensitive-string-core';
import type {
  RevealContext,
  SensitiveString,
  SensitiveValueReference,
  SensitivityClass,
} from '@platform-sec/sensitive-string-core';

import { ReferenceRefusedError, SecretPayloadError } from './errors.js';
import type { ReferenceRefusal } from './errors.js';
import type { ResolvedSecretRef, SecretRef, SecretSource } from './types.js';

/**
 * The reference pattern: send a pointer, not a value.
 *
 * `serialize()` puts the raw value on the wire and asks the transport for
 * confidentiality, which is a reasonable deal for mTLS between two services in
 * one trust domain and a poor one everywhere the payload comes to rest. A
 * payload that goes through SQS, Kafka, a `jobs` table or a webhook retry
 * buffer sits there in plaintext for as long as the retention allows, and a
 * transport that terminates at a mesh sidecar, an API gateway or a logging
 * proxy is decrypted somewhere in the middle. A reference removes the value
 * from the wire instead: the sender transmits where the value is, the receiver
 * fetches it with its own credentials, and the value never leaves the process
 * that read it.
 *
 * Minting is a pure function of the record a read returned. It is deliberately
 * not a method on `SensitiveString`, for two reasons that both come from
 * shipped behaviour. An instance does not know which store it came from,
 * because the label rule reduces a provider identifier to the logical path and
 * strips everything identifying the account, project, tenancy or host: `prod/db`
 * is what survives from an ARN, and the same logical path usually exists in
 * staging and in production. And a derived instance unions the state of its
 * sources, which is right for constraints and inverts the meaning of
 * provenance, since `token.substring(0, 4).toReference()` would mint a pointer
 * to the whole credential and the receiver could not tell the difference.
 *
 * Resolving is the half with the security content, and it is not `get()` under
 * another name. A resolver runs in the receiver, with the receiver's
 * credentials, against a path a sender chose, which is the shape of every
 * confused deputy: unconstrained, it lets anything that can enqueue a job read
 * any secret the receiver's role can read, using the receiver as the oracle. So
 * a resolver is constructed with an allowlist and refuses everything else, and
 * there is no permissive default.
 */

/** Anything a read returned: `SecretRecord`, `JsonSecretRecord`, `MultiSecretRecord`. */
export type Referenceable = { readonly ref: ResolvedSecretRef };

export interface ToReferenceOptions {
  /**
   * The logical store identity, agreed out of band with the receiver.
   *
   * Required, because nothing else in scope knows it. A `SecretSource` carries
   * no logical identity, and inventing one from the endpoint would put an
   * internal hostname into a payload, which is the disclosure the label rule
   * exists to prevent. A caller configures the name once, next to the source.
   */
  readonly store: string;
  /**
   * Pin the version the sender read. Default true.
   *
   * A reference stands in for a value, and a value does not change between the
   * send and the receive. Without the pin, a job that sits in a queue across a
   * rotation resolves to a different credential than the one the sender was
   * holding, and the failure surfaces as an authentication error in whatever
   * the job talks to, one hop away from the cause.
   *
   * The pin has a cost worth stating: a pinned reference outlives the rotation
   * that was meant to retire the old version, which is what rotation is for.
   * Keeping queue retention shorter than the rotation interval is the honest
   * fix, and it is a property of the system rather than of this library.
   * `pinVersion: false` is the other one, for a long-lived credential where
   * "current" is genuinely what the receiver wants.
   *
   * A provider that reports no version says so with `'unknown'`, which is a
   * sentinel and not a version. That is never pinned: sending it would make the
   * receiver ask its store for a version named `unknown`, and the failure would
   * describe a rotation problem that does not exist.
   */
  readonly pinVersion?: boolean;
  /**
   * An advisory class for the receiver, where the sender knows it.
   *
   * A resolver takes the more restrictive of this and its own rule, so this can
   * only tighten what the receiver does. It is never what decides the class: a
   * receiver that took a class from the wire would let a sender ask it to treat
   * a credential as `sensitive`, which turns off constant-time comparison,
   * lifts the refusal on partial queries, and lets `mask()` disclose a prefix.
   */
  readonly klass?: SensitivityClass;
}

/** One line of a resolver's allowlist: which path, and what the receiver treats it as. */
export interface ReferenceAllowEntry {
  /**
   * A logical path, or a prefix ending in a `/*` wildcard.
   *
   * A trailing `*` on a segment boundary is the only pattern supported, and it
   * covers the subtree below that prefix. There is no regex, following the
   * precedent set for region patterns: a regular expression in a security check
   * against attacker-chosen input is a backtracking bug waiting to be found.
   * Anything narrower than a subtree is written out literally.
   */
  readonly path: string;
  /**
   * The class for a whole-secret reference. Mutually exclusive with `fields`.
   *
   * An entry declaring this resolves whole-secret references only.
   */
  readonly klass?: SensitivityClass;
  /**
   * The fields of a multi-value secret this entry resolves, and the class each
   * one gets. Mutually exclusive with `klass`.
   *
   * An entry declaring this resolves field references only, and only for the
   * fields it names. The class of a field comes from this map, never from the
   * wire.
   */
  readonly fields?: Readonly<Record<string, SensitivityClass>>;
}

export interface ReferenceResolverOptions {
  /** This resolver's own store identity. A reference minted for another is refused. */
  readonly store: string;
  /** The source the receiver reads with, holding the receiver's own credentials. */
  readonly source: SecretSource;
  /**
   * What this resolver will ever hand out. Required, and the empty list is
   * legal and resolves nothing.
   *
   * An allowlist is a scope rather than an authorization decision. It says
   * which secrets this worker will ever hand out; it does not say whether the
   * particular sender was entitled to this particular secret. A system where
   * different callers deserve different secrets constructs a resolver per
   * scope, from the caller's identity.
   */
  readonly allow: readonly ReferenceAllowEntry[];
}

export interface ResolveOptions {
  /**
   * Required, for the reason `PutOptions.context` is required on the write
   * path: an operation that crosses a boundary should not run under whatever
   * ambient context happens to be lying around.
   *
   * It is installed as a child of the ambient context for the duration of the
   * fetch, so an application's `auditReveal` is inherited rather than dropped,
   * and a provider that reveals its own token to authenticate the request
   * records that reveal under the name given here.
   */
  readonly context: RevealContext;
}

export interface ReferenceResolver {
  /**
   * Fetch what a reference points at, or refuse.
   *
   * Resolving is a load, so it emits the load event a direct `get` for the same
   * ref would emit, through the source's own `onLoad`. It is not a reveal and
   * does not fire `auditReveal`: nothing here reads a raw value.
   *
   * @throws ReferenceRefusedError before the source is touched, when the
   *   reference is malformed, carries a version this build does not know, names
   *   another store, carries a path or a version this resolver will not send
   *   anywhere, or is not covered by the allowlist.
   */
  resolve(reference: unknown, options: ResolveOptions): Promise<SensitiveString<SensitivityClass>>;
}

/** A version the providers use to say they report none. Never pinned, never sent. */
const UNKNOWN_VERSION = 'unknown';

/**
 * What a version may contain.
 *
 * A version is attacker-chosen exactly as a path is, and providers put it into
 * a URL path or a query string, so it is checked against a conservative charset
 * rather than escaped. This is what keeps the version field from becoming the
 * injection the path field is not allowed to be.
 */
const VERSION_CHARSET = /^[A-Za-z0-9._:-]{1,128}$/;

/**
 * Whether a string holds a character below the space.
 *
 * Written as a scan rather than a regular expression so that the range is
 * spelled out in code points, which is what the rule is stated in, and so that
 * a source file that a reviewer greps for control characters holds none.
 */
function hasControlCharacter(text: string): boolean {
  for (let index = 0; index < text.length; index += 1) {
    if (text.charCodeAt(index) < 0x20) {
      return true;
    }
  }

  return false;
}

/**
 * What is wrong with the shape of a path, if anything.
 *
 * A path with a `.` or `..` segment is refused rather than normalized.
 * Normalizing would mean this library and the provider each holding an opinion
 * about what `kv/a/../b` means, and a disagreement between two normalizers is
 * how a path that fails an allowlist reaches the store anyway. Refusing is one
 * rule with no second opinion in it.
 */
function pathShapeFault(path: string): string | undefined {
  if (path.startsWith('/')) {
    return 'a leading slash';
  }

  if (hasControlCharacter(path)) {
    return 'a control character';
  }

  for (const segment of path.split('/')) {
    if (segment === '') {
      return 'an empty segment';
    }

    if (segment === '.' || segment === '..') {
      return 'a traversal segment';
    }
  }

  return undefined;
}

/**
 * Whether a path is covered by one pattern.
 *
 * `kv/payments/*` matches `kv/payments/stripe` and everything below it, and
 * does not match `kv/paymentsx/stripe`, because the prefix compared carries the
 * separator. The path has already passed {@link pathShapeFault}, so there is no
 * `..` in it for this to have an opinion about.
 */
function matchesPattern(pattern: string, path: string): boolean {
  if (pattern === '*') {
    return true;
  }

  if (pattern.endsWith('/*')) {
    const prefix = pattern.slice(0, -1);

    return path.startsWith(prefix) && path.length > prefix.length;
  }

  return pattern === path;
}

/**
 * The more restrictive of the receiver's class and the sender's, which is the
 * only direction a wire field may move a classification in.
 *
 * The wire class is taken only when it is strictly more restrictive on core's
 * own precedence list. A registered class that is not on that list has no
 * comparable position, so the receiver's rule stands: a custom class may be
 * stricter than either built-in one, and answering "the one with the higher
 * index" for a pair that has no order is how a loosening arrives dressed as a
 * tightening.
 */
function tighten(own: SensitivityClass, wire: SensitivityClass | undefined): SensitivityClass {
  if (wire === undefined || wire === own) {
    return own;
  }

  const ownIndex = SENSITIVITY_PRECEDENCE.indexOf(own);
  const wireIndex = SENSITIVITY_PRECEDENCE.indexOf(wire);

  if (ownIndex < 0 || wireIndex < 0) {
    return own;
  }

  return wireIndex > ownIndex ? wire : own;
}

function refuse(reason: ReferenceRefusal, message: string, path: string, version?: string): never {
  throw new ReferenceRefusedError(reason, message, path, version);
}

/**
 * Mint a reference to the value a read returned.
 *
 * The parameter is the record rather than the value, and it is typed
 * structurally so that the signature says what the function reads: a
 * `ResolvedSecretRef`, which contains no secret material by construction. A
 * `getAll` result is as mintable as a `get` result, and neither hands this
 * function a value.
 *
 * Minting performs no I/O, reads no raw value, and takes no `RevealContext`,
 * because it is not a reveal. Recording it as one would make a sink that counts
 * reveals to decide whether a credential is over-used count every message that
 * merely mentions it, which is the call the load path already made.
 *
 * @throws TypeError when handed something other than a record, or no store.
 */
export function toReference(
  record: Referenceable,
  options: ToReferenceOptions
): SensitiveValueReference {
  const ref = requireRef(record);
  const store = requireStore(options.store);
  const version = pinnedVersion(ref, options.pinVersion);
  const klass = checkHintedClass(options.klass);

  return {
    __sensitiveRef: true,
    v: 1,
    store,
    path: ref.path,
    ...(version === undefined ? {} : { version }),
    ...(klass === undefined ? {} : { klass }),
  };
}

/**
 * Mint a reference to one field of a multi-value secret.
 *
 * The field is a dot path into the payload, the same name `getJson` declares.
 * It is not checked against the record here, because a resolver only ever
 * resolves a field its own allowlist names, and that is the check that decides
 * anything.
 */
export function fieldReference(
  record: Referenceable,
  field: string,
  options: ToReferenceOptions
): SensitiveValueReference {
  if (typeof field !== 'string' || field === '') {
    throw new TypeError('A field reference needs a non-empty field name.');
  }

  return { ...toReference(record, options), field };
}

function requireRef(record: Referenceable): ResolvedSecretRef {
  const ref = (record as Partial<Referenceable> | null | undefined)?.ref;

  if (ref === undefined || typeof ref.path !== 'string' || ref.path === '') {
    throw new TypeError(
      'A reference is minted from the record a read returned, not from a value. Pass the ' +
        'result of get(), getJson() or getAll(), which carries the ref the provider resolved.'
    );
  }

  return ref;
}

function requireStore(store: string): string {
  if (typeof store !== 'string' || store === '') {
    throw new TypeError(
      'A reference needs a logical store identity, such as { store: "vault-prod" }. It is ' +
        'agreed with the receiver out of band, and is neither an endpoint nor an account id.'
    );
  }

  return store;
}

function checkHintedClass(klass: SensitivityClass | undefined): SensitivityClass | undefined {
  if (klass !== undefined && !hasPolicy(klass)) {
    throw new TypeError(`No policy is registered for sensitivity class '${klass}'.`);
  }

  return klass;
}

function pinnedVersion(
  ref: ResolvedSecretRef,
  pinVersion: boolean | undefined
): string | undefined {
  if (pinVersion === false) {
    return undefined;
  }

  const { version } = ref;

  return typeof version === 'string' && version !== '' && version !== UNKNOWN_VERSION
    ? version
    : undefined;
}

/**
 * A resolver for one store and one scope.
 *
 * @throws TypeError when the allowlist itself is malformed. That is the
 *   receiver's own configuration rather than anything a sender sent, so it
 *   fails at construction and names what is wrong, instead of refusing every
 *   reference at run time for a reason nobody can see.
 */
export function createReferenceResolver(options: ReferenceResolverOptions): ReferenceResolver {
  const store = requireStore(options.store);
  const source = options.source;
  const allow = checkAllowList(options.allow);

  if (source === undefined || source === null || typeof source.get !== 'function') {
    throw new TypeError('A reference resolver needs a SecretSource to read with.');
  }

  return {
    async resolve(
      reference: unknown,
      resolveOptions: ResolveOptions
    ): Promise<SensitiveString<SensitivityClass>> {
      const ref = checkedReference(reference, store);
      const context = requireContext(resolveOptions, ref);
      const entry = matchingEntry(ref, allow);
      const klass = tighten(classOf(entry, ref), ref.klass);
      const secretRef: SecretRef =
        ref.version === undefined ? { path: ref.path } : { path: ref.path, version: ref.version };

      // A child of whatever context is ambient, so an application's
      // `auditReveal` survives and a provider that reveals its own token to
      // authenticate this request records that reveal under the caller's name
      // rather than under nothing.
      return await withRevealContext(createChildContext(context), async () =>
        ref.field === undefined
          ? await resolveWhole(source, secretRef, klass)
          : await resolveField(source, secretRef, ref.field, klass)
      );
    },
  };
}

/**
 * The first four rules, in order: shape, format version, store, path shape.
 *
 * Order is not cosmetic. The shape check decides whether there is anything to
 * report at all, the version check has to be able to say "a reference I cannot
 * read" rather than "not a reference", the store check is what makes a stolen
 * production reference useless against a staging resolver, and the path shape
 * check runs before the allowlist so that a traversal is refused rather than
 * normalized into something an allowlist entry happens to cover.
 */
function checkedReference(reference: unknown, store: string): SensitiveValueReference {
  if (typeof reference !== 'object' || reference === null || !carriesReferenceMarker(reference)) {
    refuse('shape', 'That is not a secret reference.', '');
  }

  const version = referenceFormatVersion(reference);

  if (version !== REFERENCE_VERSION) {
    refuse(
      'format',
      `Reference format version ${version === undefined ? '(absent)' : String(version)} is not ` +
        `one this build reads. It reads version ${String(REFERENCE_VERSION)}.`,
      ''
    );
  }

  if (!isSensitiveValueReference(reference)) {
    refuse(
      'shape',
      'That reference is missing a member the format requires, or names a sensitivity class ' +
        'this process has no policy for.',
      ''
    );
  }

  if (reference.store !== store) {
    refuse(
      'store',
      `That reference was minted for another store. This resolver reads '${store}'.`,
      reference.path,
      reference.version
    );
  }

  const fault = pathShapeFault(reference.path);

  if (fault !== undefined) {
    refuse(
      'path',
      `The path in that reference contains ${fault}, so it is refused rather than normalized. ` +
        `The path is on the error's 'path' property.`,
      reference.path,
      reference.version
    );
  }

  if (reference.version !== undefined && !VERSION_CHARSET.test(reference.version)) {
    refuse(
      'version',
      'The version in that reference is outside the accepted charset, or is longer than 128 ' +
        `characters. It is on the error's 'version' property.`,
      reference.path,
      reference.version
    );
  }

  return reference;
}

/**
 * The allowlist rules: path, then kind, then field.
 *
 * Three refusals rather than one, because they mean different things to whoever
 * reads the log. Nothing covers this path at all; something covers the path but
 * this resolver hands out whole secrets there and the sender asked for a field,
 * or the reverse; the entry resolves fields and does not declare this one.
 */
function matchingEntry(
  ref: SensitiveValueReference,
  allow: readonly ReferenceAllowEntry[]
): ReferenceAllowEntry {
  const onPath = allow.filter((entry) => matchesPattern(entry.path, ref.path));

  if (onPath.length === 0) {
    refuse(
      'path',
      `No allowlist entry covers that path. The path is on the error's 'path' property.`,
      ref.path,
      ref.version
    );
  }

  const wholeSecret = ref.field === undefined;
  const onKind = onPath.filter((entry) => (entry.fields === undefined) === wholeSecret);

  if (onKind.length === 0) {
    refuse(
      'field',
      wholeSecret
        ? 'The allowlist entries covering that path resolve named fields, and that reference ' +
            'asks for the whole secret.'
        : 'The allowlist entries covering that path resolve whole secrets, and that reference ' +
            'asks for one field of one.',
      ref.path,
      ref.version
    );
  }

  const field = ref.field;
  const matched =
    field === undefined
      ? onKind[0]
      : onKind.find((entry) => Object.hasOwn(entry.fields ?? {}, field));

  if (matched === undefined) {
    refuse(
      'field',
      'No allowlist entry covering that path declares the field it names. A field this ' +
        'resolver hands out is one its own allowlist names.',
      ref.path,
      ref.version
    );
  }

  return matched;
}

/** The receiver's own class for what a reference points at, before any tightening. */
function classOf(entry: ReferenceAllowEntry, ref: SensitiveValueReference): SensitivityClass {
  if (ref.field === undefined) {
    // An entry that reached here declares `klass`, because `matchingEntry`
    // routed a whole-secret reference to one that does.
    return entry.klass ?? 'credential';
  }

  return entry.fields?.[ref.field] ?? 'credential';
}

function requireContext(options: ResolveOptions, ref: SensitiveValueReference): RevealContext {
  const context = (options as Partial<ResolveOptions> | undefined)?.context;

  if (context === undefined || typeof context.name !== 'string' || context.name === '') {
    refuse(
      'no-context',
      'Resolving a reference needs a reveal context, such as ' +
        "{ context: { name: 'charge-worker', reason: '...' } }. An operation that crosses a " +
        'boundary does not run under whatever context happens to be ambient.',
      ref.path,
      ref.version
    );
  }

  return context;
}

/**
 * A whole-secret read.
 *
 * `get` is where caching, the load event, lifetime binding and the decode guard
 * already live, which is the reason this layer adds an authorization decision
 * and not a second read path.
 */
async function resolveWhole(
  source: SecretSource,
  ref: SecretRef,
  klass: SensitivityClass
): Promise<SensitiveString<SensitivityClass>> {
  const record = await source.get(ref, { klass });

  return record.value;
}

/**
 * One field of a multi-value secret.
 *
 * Only the requested field is declared, rather than every field the entry
 * names. A `getJson` that declares a field the payload does not carry throws,
 * so declaring the entry's whole map would make resolving a reference to
 * `password` fail because some other field in the same entry had been removed
 * from the secret.
 */
async function resolveField(
  source: SecretSource,
  ref: SecretRef,
  field: string,
  klass: SensitivityClass
): Promise<SensitiveString<SensitivityClass>> {
  const record = await source.getJson(ref, { fields: { [field]: klass } });
  const value = record.fields[field];

  if (value === undefined || typeof value === 'string') {
    // Unreachable: `getJson` refuses a declared field the payload does not
    // carry, and a declared field that is not a string. The check is here
    // because the index signature cannot say so, and throwing beats handing
    // back something that is not an instance.
    throw new SecretPayloadError(
      `Secret '${ref.path}' did not yield field '${field}' as a wrapped value.`,
      ref.path,
      ref.version
    );
  }

  return value;
}

/**
 * The allowlist, checked once at construction.
 *
 * Every fault here is the receiver's own configuration, so each one throws with
 * the entry's index and what is wrong with it. An allowlist that silently
 * accepted a pattern nobody meant would be a scope wider than it reads as, and
 * the whole point of the list is that its width is legible.
 */
function checkAllowList(allow: readonly ReferenceAllowEntry[]): readonly ReferenceAllowEntry[] {
  // Checked through a second binding, so that `Array.isArray` narrows that one
  // to `any[]` rather than widening the parameter every line below reads.
  const given: unknown = allow;

  if (!Array.isArray(given)) {
    throw new TypeError(
      'A reference resolver needs an allowlist. Pass allow: [] to resolve nothing, which is ' +
        'legal and is the fail-closed default rather than a mistake.'
    );
  }

  allow.forEach((entry, index) => {
    const where = `allow[${String(index)}]`;

    if (entry === null || typeof entry !== 'object') {
      throw new TypeError(`${where} is not an allowlist entry.`);
    }

    checkPattern(entry.path, where);

    const hasKlass = entry.klass !== undefined;
    const hasFields = entry.fields !== undefined;

    if (hasKlass === hasFields) {
      throw new TypeError(
        `${where} needs exactly one of 'klass', for a whole-secret reference, and 'fields', ` +
          `for named fields of a multi-value secret.`
      );
    }

    if (hasKlass && entry.klass !== undefined && !hasPolicy(entry.klass)) {
      throw new TypeError(
        `${where} names sensitivity class '${String(entry.klass)}', which has ` +
          `no registered policy.`
      );
    }

    if (hasFields) {
      const fields: [string, SensitivityClass][] = Object.entries(entry.fields ?? {});

      if (fields.length === 0) {
        throw new TypeError(
          `${where} declares no fields, so it resolves nothing. Remove it, or name the fields ` +
            `it should resolve.`
        );
      }

      for (const [field, klass] of fields) {
        if (field === '' || !hasPolicy(klass)) {
          throw new TypeError(
            `${where} field '${field}' names sensitivity class '${String(klass)}', which has ` +
              `no registered policy.`
          );
        }
      }
    }
  });

  return [...allow];
}

/**
 * A pattern is a literal path, or a prefix with a trailing `*` on a segment
 * boundary.
 *
 * `kv/pay*` is refused rather than treated as a literal, because an operator
 * who wrote it meant a wildcard and would otherwise get an entry that matches
 * nothing and reads as though it matches a subtree.
 */
function checkPattern(pattern: string, where: string): void {
  if (typeof pattern !== 'string' || pattern === '') {
    throw new TypeError(`${where} needs a non-empty path.`);
  }

  const stars = pattern.split('*').length - 1;

  if (stars > 1 || (stars === 1 && pattern !== '*' && !pattern.endsWith('/*'))) {
    throw new TypeError(
      `${where} path '${pattern}' is not a supported pattern. A trailing '*' on a segment ` +
        `boundary is the only one, as in 'kv/payments/*', and it covers the subtree below it.`
    );
  }

  const literal = pattern === '*' ? '' : pattern.replace(/\/\*$/, '');

  if (literal !== '' && pathShapeFault(literal) !== undefined) {
    throw new TypeError(
      `${where} path '${pattern}' contains ${String(pathShapeFault(literal))}. An allowlist ` +
        `entry is written as a logical path within the store.`
    );
  }
}
