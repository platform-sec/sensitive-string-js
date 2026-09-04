import { BaseSecretSource } from '../source.js';
import type {
  ProviderPayload,
  ProviderResult,
  SecretLifetime,
  SecretMetadata,
  SecretRef,
  SecretSourceOptions,
} from '../types.js';
import type { WritePayload } from '../write.js';

/**
 * A provider that answers from a table instead of a network.
 *
 * It stands in for the one API call a real provider package makes, so the
 * shared layer's own behaviour can be driven without a transport: what a
 * provider returns, what it reports as absent, what it throws, and how many
 * times it was asked.
 */

export interface FakeSecret {
  readonly payload: ProviderPayload;
  readonly version?: string;
  readonly metadata?: SecretMetadata;
  readonly lifetime?: SecretLifetime;
}

export type FakeEntry = FakeSecret | Error | null;

export class FakeSecretSource extends BaseSecretSource {
  protected readonly sourceName = 'fake';

  /** Every ref the source was asked for, so single-flight can be counted. */
  readonly calls: SecretRef[] = [];
  /** Every write the source was asked to perform. */
  readonly writes: { ref: SecretRef; payload: WritePayload }[] = [];

  #version = 1;

  constructor(
    private readonly table: Map<string, FakeEntry>,
    options: SecretSourceOptions = {},
    /** Milliseconds each fetch takes, so concurrency has something to overlap on. */
    private readonly latencyMs = 0
  ) {
    super(options);
  }

  /** `new this` rather than `new FakeSecretSource`, so a subclass builds itself. */
  static of<T extends typeof FakeSecretSource>(
    this: T,
    entries: Readonly<Record<string, FakeEntry>>,
    options: SecretSourceOptions = {},
    latencyMs = 0
  ): InstanceType<T> {
    return new this(new Map(Object.entries(entries)), options, latencyMs) as InstanceType<T>;
  }

  set(path: string, entry: FakeEntry): void {
    this.table.set(path, entry);
  }

  protected async fetchSecret(ref: SecretRef): Promise<ProviderResult | null> {
    this.calls.push(ref);

    if (this.latencyMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, this.latencyMs));
    }

    const entry = this.table.get(ref.path);

    if (entry === undefined || entry === null) {
      return null;
    }

    if (entry instanceof Error) {
      throw entry;
    }

    return {
      payload: entry.payload,
      ref: {
        path: ref.path,
        version: entry.version ?? ref.version ?? 'v1',
        metadata: entry.metadata ?? {},
      },
      ...(entry.lifetime === undefined ? {} : { lifetime: entry.lifetime }),
    };
  }

  /** The write half, so the guard in `write.ts` has something to drive. */
  async writeSecret(
    ref: SecretRef,
    payload: WritePayload
  ): Promise<{
    path: string;
    version: string;
    metadata: SecretMetadata;
  }> {
    this.writes.push({ ref, payload });
    this.#version += 1;

    const version = `v${String(this.#version)}`;

    this.table.set(ref.path, {
      payload:
        payload.kind === 'string'
          ? { kind: 'string', value: payload.value }
          : { kind: 'map', value: { ...payload.value } },
      version,
    });

    return await Promise.resolve({ path: ref.path, version, metadata: {} });
  }
}

/**
 * A source whose write lands and whose next read fails.
 *
 * Stands in for a provider that accepted the write and then refused the read:
 * an expired token, a policy that grants write and not read, a transient
 * outage. From the caller's side the outcome is the same, the stored value
 * cannot be confirmed.
 */
export class UnreadableAfterWriteSource extends FakeSecretSource {
  override async writeSecret(
    ref: SecretRef,
    payload: WritePayload
  ): Promise<{ path: string; version: string; metadata: SecretMetadata }> {
    const written = await super.writeSecret(ref, payload);
    this.set(ref.path, new Error('read path is down'));

    return written;
  }
}

/** A source whose write silently stores something other than what it was sent. */
export class CorruptingSecretSource extends FakeSecretSource {
  override async writeSecret(
    ref: SecretRef,
    payload: WritePayload
  ): Promise<{ path: string; version: string; metadata: SecretMetadata }> {
    const corrupted: WritePayload =
      payload.kind === 'string'
        ? { kind: 'string', value: `${payload.value}-corrupted` }
        : {
            kind: 'map',
            value: Object.fromEntries(
              Object.entries(payload.value).map(([key, value]) => [key, `${value}-corrupted`])
            ),
          };

    return super.writeSecret(ref, corrupted);
  }
}
