import { SecretPayloadError } from '@platform-sec/sensitive-string-secrets';
import type { ResolvedSecretRef, SecretMetadata } from '@platform-sec/sensitive-string-secrets';

/**
 * The KV wire shapes.
 *
 * KV v2 nests the payload at `data.data` with metadata at `data.metadata`. KV
 * v1 puts it at `data`. Getting this wrong yields a payload whose fields are
 * `data` and `metadata` rather than the ones the caller named, so the mount
 * version is explicit in the configuration rather than guessed, and the
 * mismatch produces a diagnostic naming the likely cause.
 */

export type KvVersion = 1 | 2;

/** One configured mount and the KV engine version behind it. */
export interface VaultMount {
  /** The mount point, without slashes: `kv`, `secret`. */
  readonly path: string;
  readonly kv: KvVersion;
}

/** A scheme and authority at the head of a path, which a caller sometimes pastes in. */
const IS_URL = /^[a-z][a-z0-9+.-]*:\/\//i;

/**
 * Reject a path that is a URL.
 *
 * A ref's path is the logical path within the store, which is what becomes the
 * label and what the request path is built from. A pasted endpoint would
 * produce a request to a path that does not exist and a label carrying an
 * internal hostname and port, so it is refused at the boundary rather than
 * silently normalized into something that only half works.
 */
export function assertUnversioned(path: string, version: string | undefined): void {
  if (version !== undefined) {
    throw new TypeError(
      `Mount '${splitMount(path).mount}' is configured as KV v1, which overwrites in place ` +
        `and has no versions, so version '${version}' cannot be served. The request would ` +
        `silently return the current value instead. Configure the mount as KV v2, or drop ` +
        `the version.`
    );
  }
}

export function assertLogicalPath(path: string): void {
  if (IS_URL.test(path)) {
    throw new TypeError(
      `A Vault ref path is the logical path within the store, such as 'kv/prod/db', ` +
        `not a URL. The endpoint belongs on the source, and putting it here would put an ` +
        `internal hostname into every log line that touches the value.`
    );
  }
}

/** Split `kv/prod/db` into the mount and the path below it. */
export function splitMount(path: string): { mount: string; rest: string } {
  const trimmed = path.replace(/^\/+/, '');
  const slash = trimmed.indexOf('/');

  if (slash === -1) {
    return { mount: trimmed, rest: '' };
  }

  return { mount: trimmed.slice(0, slash), rest: trimmed.slice(slash + 1) };
}

/** The request path for a KV read, which differs by engine version. */
export function kvReadPath(path: string, version: KvVersion): string {
  if (version === 1) {
    return path.replace(/^\/+/, '');
  }

  const { mount, rest } = splitMount(path);

  return rest === '' ? `${mount}/data` : `${mount}/data/${rest}`;
}

/** The request path for a KV write. */
export function kvWritePath(path: string, version: KvVersion): string {
  return kvReadPath(path, version);
}

/** The request path for a KV v2 metadata read, which KV v1 has no equivalent of. */
export function kvMetadataPath(path: string): string {
  const { mount, rest } = splitMount(path);

  return rest === '' ? `${mount}/metadata` : `${mount}/metadata/${rest}`;
}

export interface KvRead {
  readonly data: Record<string, unknown>;
  /**
   * The concrete version Vault served.
   *
   * `'unversioned'` for KV v1, which overwrites in place and has no versions,
   * matching what a KV v1 write reports.
   */
  readonly version: string;
  readonly metadata: SecretMetadata;
  /**
   * Seconds, straight off the response.
   *
   * Not a deadline for a KV read. Measured on Vault 1.21.4 and OpenBao 2.6.2, a
   * KV v2 read reports 0 and a KV v1 read reports the mount's default TTL,
   * 2764800 seconds, with an empty `leaseId`. The v1 number looks like a
   * 32-day lease and is not one: nothing about the secret expires when it runs
   * out. `leaseId` is what says whether a lease exists.
   */
  readonly leaseDurationSeconds: number;
  /** Empty for a KV read on both engine versions. A lease exists only when this does. */
  readonly leaseId: string;
  readonly renewable: boolean;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function scalarMetadata(source: Record<string, unknown>, keys: readonly string[]): SecretMetadata {
  const metadata: Record<string, string | number | boolean | undefined> = {};

  for (const key of keys) {
    const value = source[key];

    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
      metadata[key] = value;
    }
  }

  return metadata;
}

/**
 * Read a KV response into a payload, a version, and non-secret metadata.
 *
 * `data.metadata.custom_metadata` is not secret and goes on the ref's metadata.
 * `data.metadata.version` is the concrete version, which is what the audit
 * trail needs: a record that says the caller asked for the current version
 * records nothing.
 */
export function parseKvResponse(
  body: unknown,
  kv: KvVersion,
  ref: { path: string; version?: string }
): KvRead {
  const envelope = asRecord(body);
  const version = ref.version ?? 'current';

  if (envelope === undefined) {
    throw new SecretPayloadError(
      `Secret '${ref.path}' version '${version}' returned no readable body.`,
      ref.path,
      version
    );
  }

  const leaseDurationSeconds =
    typeof envelope['lease_duration'] === 'number' ? envelope['lease_duration'] : 0;
  const leaseId = typeof envelope['lease_id'] === 'string' ? envelope['lease_id'] : '';
  const renewable = envelope['renewable'] === true;
  const outer = asRecord(envelope['data']);

  if (outer === undefined) {
    throw new SecretPayloadError(
      `Secret '${ref.path}' version '${version}' returned no data.`,
      ref.path,
      version
    );
  }

  if (kv === 2) {
    const inner = asRecord(outer['data']);
    const metadata = asRecord(outer['metadata']) ?? {};

    if (inner === undefined) {
      throw new SecretPayloadError(
        `Secret '${ref.path}' version '${version}' does not have the shape of a KV v2 read. ` +
          `The mount is configured as KV v2; if it is really KV v1, configure it as such.`,
        ref.path,
        version
      );
    }

    const custom = asRecord(metadata['custom_metadata']) ?? {};
    const served = metadata['version'];

    return {
      data: inner,
      version: typeof served === 'number' || typeof served === 'string' ? String(served) : version,
      metadata: {
        ...scalarMetadata(metadata, ['created_time', 'deletion_time', 'destroyed']),
        ...scalarMetadata(custom, Object.keys(custom)),
      },
      leaseDurationSeconds,
      leaseId,
      renewable,
    };
  }

  const keys = Object.keys(outer);

  // A KV v2 response read as KV v1 arrives with exactly these two keys, and
  // wrapping them would hand the caller fields named `data` and `metadata`
  // rather than the ones they declared.
  if (keys.length === 2 && keys.includes('data') && keys.includes('metadata')) {
    throw new SecretPayloadError(
      `Secret '${ref.path}' version '${version}' has only the keys 'data' and 'metadata', ` +
        `which is the shape of a KV v2 read. The mount is configured as KV v1; configure ` +
        `it as KV v2.`,
      ref.path,
      version
    );
  }

  return {
    data: outer,
    // Not `version`. KV v1 overwrites in place, so echoing back whatever the
    // caller asked for would report an alias as a concrete version, which is
    // the one thing `ResolvedSecretRef.version` promises not to do.
    version: 'unversioned',
    metadata: {},
    leaseDurationSeconds,
    leaseId,
    renewable,
  };
}

/** The body a KV write takes, which nests under `data` for v2 and not for v1. */
export function kvWriteBody(fields: Readonly<Record<string, string>>, kv: KvVersion): unknown {
  return kv === 2 ? { data: fields } : { ...fields };
}

/** The version a KV write reports, which only v2 has. */
export function kvWrittenVersion(body: unknown, kv: KvVersion): string {
  if (kv === 1) {
    // KV v1 overwrites in place and has no versions. The README says so, rather
    // than this package inventing a number that means nothing.
    return 'unversioned';
  }

  const outer = asRecord(asRecord(body)?.['data']);
  const version = outer?.['version'];

  return typeof version === 'number' || typeof version === 'string' ? String(version) : 'unknown';
}

/** The resolved ref for a KV read. */
export function kvResolvedRef(
  ref: { path: string; version?: string },
  read: KvRead
): ResolvedSecretRef {
  return {
    path: ref.path,
    version: read.version,
    metadata: read.metadata,
  };
}
