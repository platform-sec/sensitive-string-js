import { basename } from 'node:path';
import { readdir, readFile, stat } from 'node:fs/promises';
import { BaseSecretSource, logicalLabel, watchFile } from '@platform-sec/sensitive-string-secrets';
import type {
  FileWatcher,
  MultiSecretRecord,
  ProviderResult,
  ResolvedSecretRef,
  SecretLifetime,
  SecretRef,
  SecretSourceOptions,
  GetAllOptions,
  WatchOptions,
} from '@platform-sec/sensitive-string-secrets';

import { jwtExpiry } from './token.js';

/**
 * A mounted Secret volume.
 *
 * The usual way a workload reads a Secret is a mounted volume, not an API call,
 * and by the trust-boundary test that puts it in the configuration loaders row:
 * the files are plaintext on a tmpfs the container can already read, no key is
 * needed, and the question that matters is what happens to the copy the kubelet
 * wrote.
 *
 * It ships here anyway, because a user who thinks of this as "reading a Secret"
 * will look in this package first, and sending them elsewhere with no
 * explanation is worse than a small overlap. What it does is deliberately thin:
 * it reads the directory, applies a classification, and wraps. It does not
 * delete the files, does not remap them into `process.env`, and does not claim
 * to remove the original.
 *
 * The kubelet rewrites a mounted Secret when it changes, on a sync period
 * rather than immediately, so a value read at boot goes stale silently. That is
 * what `watch()` is for, and the atomic swap the kubelet performs is exactly
 * the several-events-per-change case the shared watcher debounces.
 */
export interface K8sMountedSourceOptions extends SecretSourceOptions {
  /**
   * The directory a relative ref resolves against.
   *
   * A ref is the mount directory, so `{ basePath: '/etc/secrets' }` with
   * `getAll('db-creds')` reads `/etc/secrets/db-creds`, and an absolute ref
   * needs no base at all. There is deliberately no "the one mount" mode: a ref
   * that names nothing would have no label to derive and no cache key to
   * separate it from the next mount a caller adds.
   */
  readonly basePath?: string | undefined;
  /** Bind the `exp` claim of a `token` file as a deadline. Off by default. */
  readonly readTokenExpiry?: boolean | undefined;
  /**
   * Include entries whose names begin with `..`.
   *
   * Off by default, and this is the whole reason the reader is not a plain
   * `readdir`. A kubelet mount holds a timestamped data directory and a
   * `..data` symlink beside the visible keys, and including them would report
   * the same secret twice under two names, one of which changes on every
   * update.
   */
  readonly includeHiddenEntries?: boolean | undefined;
}

/** The default mount path of a projected service account token. */
export const SERVICE_ACCOUNT_PATH = '/var/run/secrets/kubernetes.io/serviceaccount';

export class K8sMountedSource extends BaseSecretSource {
  protected readonly sourceName = 'k8s-mounted';

  readonly #basePath: string | undefined;
  readonly #readTokenExpiry: boolean;
  readonly #includeHidden: boolean;

  constructor(options: K8sMountedSourceOptions = {}) {
    super(options);

    this.#basePath = options.basePath;
    this.#readTokenExpiry = options.readTokenExpiry ?? false;
    this.#includeHidden = options.includeHiddenEntries ?? false;
  }

  /** The mount's last path segment. A container path names no host. */
  protected override deriveLabel(ref: SecretRef): string {
    return logicalLabel(basename(this.#resolve(ref)));
  }

  protected async fetchSecret(ref: SecretRef): Promise<ProviderResult | null> {
    const dir = this.#resolve(ref);
    const resolved: ResolvedSecretRef = {
      path: this.deriveLabel(ref),
      version: 'mounted',
      metadata: { mount: dir },
    };

    let entries: string[];

    try {
      entries = await readdir(dir);
    } catch (error) {
      if (
        typeof error === 'object' &&
        error !== null &&
        (error as { code?: unknown }).code === 'ENOENT'
      ) {
        return null;
      }

      throw error;
    }

    const data: Record<string, string> = {};

    for (const entry of entries) {
      // `..data` and `..2026_09_03_...` are the kubelet's own bookkeeping.
      if (!this.#includeHidden && entry.startsWith('..')) {
        continue;
      }

      const full = `${dir}/${entry}`;

      // `stat` rather than the dirent, because every visible key in a kubelet
      // mount is a symlink into `..data` and a dirent reports the link.
      const stats = await stat(full).catch(() => undefined);

      if (stats === undefined || !stats.isFile()) {
        continue;
      }

      data[entry] = await readFile(full, 'utf8');
    }

    const lifetime = this.#readTokenExpiry ? this.#tokenLifetime(data, resolved) : undefined;

    return {
      payload: { kind: 'map', value: data },
      ref: resolved,
      ...(lifetime === undefined ? {} : { lifetime }),
    };
  }

  /**
   * Re-read the mount when the kubelet rewrites it.
   *
   * Each change produces new instances. The ones already handed out stay valid,
   * because nothing can reach them, so an in-flight request holding the
   * previous credential finishes with it. `onChange` receives the previous
   * record so a caller can drain with it.
   */
  watch(
    ref: SecretRef | string,
    options: GetAllOptions,
    watchOptions: WatchOptions<MultiSecretRecord>
  ): FileWatcher {
    const normalized = typeof ref === 'string' ? { path: ref } : ref;
    const dir = this.#resolve(normalized);

    return watchFile(
      dir,
      async () => {
        // Past the cache, so a re-read after a change is a real read.
        this.refresh(normalized);

        return await this.getAll(normalized, options);
      },
      watchOptions
    );
  }

  #resolve(ref: SecretRef): string {
    if (ref.path.startsWith('/') || ref.path.startsWith('.')) {
      return ref.path;
    }

    if (this.#basePath === undefined || this.#basePath === '') {
      throw new TypeError(
        `K8sMountedSource needs a directory to resolve '${ref.path}' against. Pass ` +
          `{ basePath } to the constructor, or use an absolute path as the ref.`
      );
    }

    return `${this.#basePath}/${ref.path}`;
  }

  #tokenLifetime(
    data: Readonly<Record<string, string>>,
    ref: ResolvedSecretRef
  ): SecretLifetime | undefined {
    const token = data['token'];

    if (token === undefined) {
      return undefined;
    }

    const expiresAt = jwtExpiry(token, ref);

    return expiresAt === undefined ? undefined : { expiresAt };
  }
}
