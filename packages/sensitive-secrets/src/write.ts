import { SensitiveString, containsRedactionMarker } from '@platform-sec/sensitive-string-core';
import type { RevealContext, SensitivityClass } from '@platform-sec/sensitive-string-core';

import { SecretWriteRefusedError } from './errors.js';
import { normalizeRef } from './source.js';
import type { FieldMap, ResolvedSecretRef, SecretRef, SecretSource } from './types.js';

/**
 * The write path, in its own entry point.
 *
 * A read integration is the cheap half of this row because nothing is
 * transmitted. A write is a transmit, and it is the one place in the category
 * where a redaction marker gets persisted rather than merely sent: a
 * `SensitiveString` handed to a provider's write call stringifies to
 * `[REDACTED:credential]` and is stored under that value. The write succeeds,
 * the provider reports success, and every consumer that reads the secret
 * afterwards receives the literal marker as its database password. The first
 * sign is an authentication failure in a different service.
 *
 * It lives behind `@platform-sec/sensitive-string-secrets/write` so an
 * application that only reads never loads it, and a build that never imports it
 * can be verified to contain no write call.
 */

/** Any wrapped value, whatever its class. */
type AnySensitive = SensitiveString<SensitivityClass>;

/** What a provider's write call accepts. */
export type WritePayload =
  | { readonly kind: 'string'; readonly value: string }
  | { readonly kind: 'map'; readonly value: Readonly<Record<string, string>> };

/**
 * The write half of a provider.
 *
 * Separate from `SecretSource` so a read-only source is not forced to declare a
 * method it refuses, and so `isWritable` is a real question with a real answer.
 */
export interface SecretWriter {
  /** Store a new version. Returns the ref the provider resolved the write to. */
  writeSecret(ref: SecretRef, payload: WritePayload): Promise<ResolvedSecretRef>;
}

export type WritableSecretSource = SecretSource & SecretWriter;

export function isWritable(source: SecretSource): source is WritableSecretSource {
  return typeof (source as Partial<SecretWriter>).writeSecret === 'function';
}

export interface PutOptions {
  /**
   * Required.
   *
   * Writing a secret is not something to do under an ambient context that
   * happens to be lying around, and the reveal that produces the outgoing bytes
   * belongs in the audit trail under the caller's own name.
   */
  readonly context: RevealContext;
  /**
   * Read the new version back and compare it with what was written.
   *
   * On by default. It costs one extra API call on an operation that happens on
   * a rotation schedule, and it turns a silently corrupted secret into a failed
   * rotation. Turning it off trades a real guarantee for one request.
   */
  readonly verifyReadBack?: boolean;
}

/** Every string that is about to be transmitted, refused if any holds a marker. */
function refuseMarkers(
  values: readonly { readonly field: string | undefined; readonly value: string }[],
  ref: SecretRef
): void {
  for (const { field, value } of values) {
    // Core's detector rather than a literal. It knows the default prefix, the
    // constant redaction of any policy an application registered, and the
    // `markerPattern` a value-dependent one declares, none of which a hardcoded
    // string reaches. A deployment that customised its redaction had no
    // protection here before, and nothing said so.
    if (!containsRedactionMarker(value)) {
      continue;
    }

    const where = field === undefined ? '' : ` field '${field}'`;

    throw new SecretWriteRefusedError(
      'marker',
      `Refusing to write secret '${ref.path}'${where}: the bytes about to be sent contain ` +
        `a redaction marker. A SensitiveString was stringified rather than revealed, most ` +
        `often by template interpolation or JSON.stringify. Call reveal() with a context, ` +
        `or hand the instance to put() and let it do the reveal.`,
      ref.path,
      ref.version
    );
  }
}

function requireContext(options: PutOptions, ref: SecretRef): RevealContext {
  const context = options.context as RevealContext | undefined;

  if (context === undefined || typeof context.name !== 'string' || context.name === '') {
    throw new SecretWriteRefusedError(
      'no-context',
      `Refusing to write secret '${ref.path}' with no reveal context. Pass ` +
        `{ context: { name: 'rotate-db-credential', reason: '...' } }.`,
      ref.path,
      ref.version
    );
  }

  return context;
}

/** Reveal an instance under the write's context, or take a plain string as given. */
function outgoing(value: AnySensitive | string, context: RevealContext): string {
  return value instanceof SensitiveString ? value.reveal(context) : value;
}

/**
 * Write a single-value secret.
 *
 * @throws SecretWriteRefusedError before any transport call when no context was
 *   given or the outgoing bytes contain a redaction marker, and after the write
 *   when the read-back does not match.
 */
export async function put(
  source: WritableSecretSource,
  ref: SecretRef | string,
  value: AnySensitive | string,
  options: PutOptions
): Promise<ResolvedSecretRef> {
  const normalized = normalizeRef(ref);
  const context = requireContext(options, normalized);
  const raw = outgoing(value, context);

  refuseMarkers([{ field: undefined, value: raw }], normalized);

  const written = await source.writeSecret(normalized, { kind: 'string', value: raw });

  if (options.verifyReadBack !== false) {
    const readBack = await readCurrent(source, normalized, written, async () => {
      const record = await source.get({ path: normalized.path });

      return record.value.equals(raw, context);
    });

    if (!readBack) {
      throw new SecretWriteRefusedError(
        'read-back',
        `Secret '${normalized.path}' version '${written.version}' did not read back as ` +
          `written. The stored value is not what this process sent.`,
        normalized.path,
        written.version
      );
    }
  }

  return written;
}

/**
 * Read the current version back and report whether it matches.
 *
 * The current version, not the one the write reported. Pinning the written
 * version would seem more precise and is weaker: it would pass even when a
 * later version immediately superseded ours, and the guarantee worth having is
 * that a reader now gets what this process sent. It also avoids pinning a
 * version identifier that is not one, since a store that overwrites in place
 * has no versions to pin and reports a placeholder.
 *
 * A concurrent rotation makes this fail. That is a true report rather than a
 * false alarm: what is stored is not what this process sent. Rotations are
 * scheduled, so two of them racing is a deployment problem worth hearing about.
 *
 * Any failure of the read itself is reported as a failed verification rather
 * than escaping as a decode or lookup error, because from the caller's side the
 * outcome is the same: the write cannot be confirmed.
 */
async function readCurrent(
  source: WritableSecretSource,
  ref: SecretRef,
  written: ResolvedSecretRef,
  compare: () => Promise<boolean>
): Promise<boolean> {
  source.refresh({ path: ref.path });

  try {
    return await compare();
  } catch (error) {
    if (error instanceof SecretWriteRefusedError) {
      throw error;
    }

    throw new SecretWriteRefusedError(
      'read-back',
      `Secret '${ref.path}' version '${written.version}' could not be read back after the ` +
        `write, so the stored value is unconfirmed.`,
      ref.path,
      written.version
    );
  }
}

/**
 * Write a multi-value secret.
 *
 * The map-shaped write exists because the stores this row starts with are
 * map-shaped: a Vault KV path and a Kubernetes Secret hold named fields, and a
 * single-value write against one of them would have to invent a field name.
 */
export async function putJson(
  source: WritableSecretSource,
  ref: SecretRef | string,
  fields: Readonly<Record<string, AnySensitive | string>>,
  options: PutOptions
): Promise<ResolvedSecretRef> {
  const normalized = normalizeRef(ref);
  const context = requireContext(options, normalized);

  const raw: Record<string, string> = {};

  for (const [field, value] of Object.entries(fields)) {
    raw[field] = outgoing(value, context);
  }

  refuseMarkers(
    Object.entries(raw).map(([field, value]) => ({ field, value })),
    normalized
  );

  const written = await source.writeSecret(normalized, { kind: 'map', value: raw });

  if (options.verifyReadBack !== false) {
    const declared: FieldMap = Object.fromEntries(
      Object.keys(raw).map((field) => [field, 'credential' as const])
    );

    let mismatched: string | undefined;

    await readCurrent(source, normalized, written, async () => {
      const readBack = await source.getJson({ path: normalized.path }, { fields: declared });

      for (const [field, value] of Object.entries(raw)) {
        const stored = (readBack.fields as Record<string, unknown>)[field];

        if (!(stored instanceof SensitiveString) || !stored.equals(value, context)) {
          mismatched = field;
          break;
        }
      }

      return true;
    });

    if (mismatched !== undefined) {
      throw new SecretWriteRefusedError(
        'read-back',
        `Secret '${normalized.path}' version '${written.version}' field '${mismatched}' did ` +
          `not read back as written. The stored value is not what this process sent.`,
        normalized.path,
        written.version
      );
    }
  }

  return written;
}
