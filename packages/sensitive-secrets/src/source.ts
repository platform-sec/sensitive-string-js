import { SensitiveString } from '@platform-sec/sensitive-string-core';
import type {
  CompiledClassification,
  FieldClass,
  SensitivityClass,
} from '@platform-sec/sensitive-string-core';

import { allSpec, jsonSpec } from './classify.js';
import { SecretCache, cacheKey, refPrefix } from './cache.js';
import { asObject, parsePayload } from './decode.js';
import { SecretNotFoundError, SecretPayloadError } from './errors.js';
import { logicalLabel } from './label.js';
import { lifetimeOptions, materialize } from './materialize.js';
import type { Materialized } from './materialize.js';
import type {
  FieldMap,
  FieldSets,
  GetAllOptions,
  GetJsonOptions,
  GetOptions,
  JsonFields,
  JsonSecretRecord,
  MultiSecretRecord,
  ProviderResult,
  ResolvedSecretRef,
  SecretLifetime,
  SecretLoadEvent,
  SecretRecord,
  SecretRef,
  SecretSource,
  SecretSourceOptions,
} from './types.js';

/** A ref given either way. A bare string is the common call and means no version. */
export function normalizeRef(ref: SecretRef | string): SecretRef {
  const normalized = typeof ref === 'string' ? { path: ref } : ref;

  if (typeof normalized.path !== 'string' || normalized.path === '') {
    throw new TypeError('A secret ref needs a non-empty path.');
  }

  return normalized;
}

/**
 * A stable description of what a call asked for.
 *
 * Two reads of one path under different classifications produce different
 * instances, so the cache has to tell them apart. Rules contribute their source
 * and flags rather than their identity, so a spec rebuilt on every call still
 * hits the same entry.
 */
function shapeKey(kind: string, parts: readonly unknown[]): string {
  return `${kind}:${JSON.stringify(parts, (_key, value) =>
    value instanceof RegExp ? `re:${value.source}:${value.flags}` : (value as unknown)
  )}`;
}

/** Any wrapped value, whatever its class. */
type AnySensitive = SensitiveString<SensitivityClass>;

/** The earliest deadline among a set of instances, as an ISO string. */
function earliestExpiry(instances: readonly AnySensitive[]): string | undefined {
  let earliest: Date | undefined;

  for (const instance of instances) {
    const deadline = instance.expiresAt;

    if (deadline !== undefined && (earliest === undefined || deadline < earliest)) {
      earliest = deadline;
    }
  }

  return earliest?.toISOString();
}

/** What a load produced, before it is shaped into the record a caller sees. */
interface Loaded {
  readonly ref: ResolvedSecretRef;
  readonly instances: readonly AnySensitive[];
}

interface SingleLoaded<C extends SensitivityClass> extends Loaded {
  readonly record: SecretRecord<C>;
}

interface BulkLoaded extends Loaded {
  readonly ref: ResolvedSecretRef;
  readonly materialized: Materialized;
}

/**
 * The base every provider package extends.
 *
 * A provider supplies its name and one method: fetch this ref, return the
 * payload and the resolved ref, or null if the provider says it is absent.
 * Everything else in the read path is here, which is the point of a shared
 * layer: eight providers doing the same five things independently is how the
 * label rule ends up different in each one.
 *
 * The provider's response object never reaches this class. It is destructured
 * inside the provider package, and what crosses the boundary is a
 * `ProviderResult` holding the payload and non-secret metadata.
 */
export abstract class BaseSecretSource implements SecretSource {
  readonly #cache: SecretCache;
  readonly #onLoad: ((event: SecretLoadEvent) => void) | undefined;

  constructor(options: SecretSourceOptions = {}) {
    this.#cache = new SecretCache(options.cache ?? {});
    this.#onLoad = options.onLoad;
  }

  /** The provider package's own name, as it appears on a load event. */
  protected abstract readonly sourceName: string;

  /**
   * One provider round trip.
   *
   * Returns null where the provider reports the secret or the version as
   * absent. An authorization failure is not an absence and must throw, so
   * `getOptional` does not turn a broken policy into a missing secret.
   */
  protected abstract fetchSecret(ref: SecretRef): Promise<ProviderResult | null>;

  /**
   * The label for a ref, before any caller override.
   *
   * The default reduces the path to the logical path within the store. A
   * provider whose ref carries an account-scoped identifier overrides this and
   * strips it, putting the full identifier on `ResolvedSecretRef.metadata`
   * instead.
   */
  protected deriveLabel(ref: SecretRef): string {
    return logicalLabel(ref.path);
  }

  async get<C extends SensitivityClass = 'credential'>(
    ref: SecretRef | string,
    options: GetOptions<C> = {}
  ): Promise<SecretRecord<C>> {
    const normalized = normalizeRef(ref);
    const klass = (options.klass ?? 'credential') as C;
    const label = options.label ?? this.deriveLabel(normalized);
    const key = cacheKey(normalized, shapeKey('get', [klass, label, options.ttl]));

    const started = Date.now();
    let fetched = false;

    const loaded = await this.#cache.load(
      key,
      async (): Promise<SingleLoaded<C>> => {
        const result = await this.fetchSecret(normalized);

        if (result === null) {
          throw new SecretNotFoundError(
            `Secret '${normalized.path}'${
              normalized.version === undefined ? '' : ` version '${normalized.version}'`
            } was not found.`,
            normalized.path,
            normalized.version
          );
        }

        fetched = true;

        if (result.payload.kind === 'map') {
          throw new SecretPayloadError(
            `Secret '${result.ref.path}' version '${result.ref.version}' holds a set of ` +
              `named fields rather than one value. Use getJson() or getAll().`,
            result.ref.path,
            result.ref.version
          );
        }

        const lifetime = this.#lifetime(result, options.ttl);
        const value = new SensitiveString<C>(
          result.payload.value,
          klass,
          label,
          lifetimeOptions(lifetime)
        );

        return { ref: result.ref, record: { value, ref: result.ref }, instances: [value] };
      },
      (value) => value.instances
    );

    this.#emit({
      kind: 'single',
      source: this.sourceName,
      ref: loaded.ref,
      cached: !fetched,
      durationMs: Date.now() - started,
      expiresAt: earliestExpiry(loaded.instances),
      klass,
      label,
    });

    return loaded.record;
  }

  async getOptional<C extends SensitivityClass = 'credential'>(
    ref: SecretRef | string,
    options: GetOptions<C> = {}
  ): Promise<SecretRecord<C> | null> {
    try {
      return await this.get(ref, options);
    } catch (error) {
      // Absence only. An authorization failure, a decode failure and an
      // unreachable provider all keep throwing, so a broken policy never
      // arrives as a missing secret.
      if (error instanceof SecretNotFoundError) {
        return null;
      }

      throw error;
    }
  }

  async getJson<F extends FieldMap>(
    ref: SecretRef | string,
    options: GetJsonOptions<F>
  ): Promise<JsonSecretRecord<F>> {
    const normalized = normalizeRef(ref);
    const label = options.label ?? this.deriveLabel(normalized);
    const declared = Object.keys(options.fields);
    const key = cacheKey(
      normalized,
      shapeKey('json', [options.fields, options.rules, options.fallback, label, options.ttl])
    );

    const loaded = await this.#bulk(
      normalized,
      key,
      label,
      options.ttl,
      jsonSpec(options),
      declared
    );

    const fields: Record<string, unknown> = {};
    const extraFields = new Map<string, SensitiveString<SensitivityClass>>();
    const extraPlain = new Map<string, string>();

    for (const [path, value] of loaded.materialized.fields) {
      if (declared.includes(path)) {
        fields[path] = value;
      } else {
        extraFields.set(path, value);
      }
    }

    for (const path of loaded.materialized.keys) {
      if (loaded.materialized.fields.has(path)) {
        continue;
      }

      const raw = loaded.materialized.raw.get(path);

      if (declared.includes(path)) {
        fields[path] = raw;
      } else if (typeof raw === 'string') {
        extraPlain.set(path, raw);
      }
    }

    const extra: FieldSets = { fields: extraFields, plain: extraPlain };

    return {
      ref: loaded.ref,
      fields: fields as JsonFields<F>,
      extra,
      keys: loaded.materialized.keys,
    };
  }

  async getAll(ref: SecretRef | string, options: GetAllOptions): Promise<MultiSecretRecord> {
    const normalized = normalizeRef(ref);
    const label = options.label ?? this.deriveLabel(normalized);
    const key = cacheKey(
      normalized,
      shapeKey('all', [options.fields, options.rules, options.fallback, label, options.ttl])
    );

    const loaded = await this.#bulk(
      normalized,
      key,
      label,
      options.ttl,
      allSpec(options),
      Object.keys(options.fields ?? {})
    );

    return {
      ref: loaded.ref,
      fields: loaded.materialized.fields,
      plain: loaded.materialized.plain,
      keys: loaded.materialized.keys,
    };
  }

  refresh(ref: SecretRef | string): void {
    this.#cache.deletePrefix(refPrefix(normalizeRef(ref)));
  }

  /** Drop every cached entry. Used by a write's read-back, and by a caller shutting down. */
  protected clearCache(): void {
    this.#cache.clear();
  }

  /** The decode, classify, wrap pipeline, shared by `getJson` and `getAll`. */
  async #bulk(
    ref: SecretRef,
    key: string,
    label: string,
    ttl: number | undefined,
    spec: CompiledClassification,
    declared: readonly string[]
  ): Promise<BulkLoaded> {
    const started = Date.now();
    let fetched = false;

    const loaded = await this.#cache.load(
      key,
      async (): Promise<BulkLoaded> => {
        const result = await this.fetchSecret(ref);

        if (result === null) {
          throw new SecretNotFoundError(
            `Secret '${ref.path}'${
              ref.version === undefined ? '' : ` version '${ref.version}'`
            } was not found.`,
            ref.path,
            ref.version
          );
        }

        fetched = true;

        const payload =
          result.payload.kind === 'string'
            ? parsePayload(result.payload.value, result.ref)
            : asObject(result.payload.value, result.ref);

        const lifetime = this.#lifetime(result, ttl);
        const materialized = materialize({
          payload,
          ref: result.ref,
          spec,
          label,
          lifetime,
          declared,
        });

        return {
          ref: result.ref,
          materialized,
          instances: [...materialized.fields.values()],
        };
      },
      (value) => value.instances
    );

    this.#emit({
      kind: 'bulk',
      source: this.sourceName,
      ref: loaded.ref,
      cached: !fetched,
      durationMs: Date.now() - started,
      expiresAt: earliestExpiry(loaded.instances),
      keys: loaded.materialized.keys,
      counts: loaded.materialized.counts satisfies Readonly<Record<FieldClass, number>>,
    });

    return loaded;
  }

  /**
   * The lifetime bound to the values of one load.
   *
   * A provider-supplied deadline wins. `GetOptions.ttl` is for providers that
   * supply none, which is why it is ignored rather than merged where one
   * arrived: a caller's guess must not shorten or extend what the provider
   * actually said.
   */
  #lifetime(result: ProviderResult, ttl: number | undefined): SecretLifetime | undefined {
    if (result.lifetime !== undefined) {
      return result.lifetime;
    }

    return ttl === undefined ? undefined : { ttl };
  }

  #emit(event: SecretLoadEvent): void {
    // Errors propagate. A load hook that fails silently is an audit gap, which
    // is the opposite of core's `onExpire`: that one is a lifecycle callback
    // and swallowing is right for it.
    this.#onLoad?.(event);
  }
}
