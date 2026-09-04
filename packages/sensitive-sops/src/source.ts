import { access, readFile } from 'node:fs/promises';
import { basename } from 'node:path';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import type { ClassificationSpec } from '@platform-sec/sensitive-string-core';
import {
  BaseSecretSource,
  SecretPayloadError,
  logicalLabel,
  parsePayload,
  watchFile,
} from '@platform-sec/sensitive-string-secrets';
import type {
  FileWatcher,
  GetAllOptions,
  MultiSecretRecord,
  ProviderResult,
  ResolvedSecretRef,
  SecretRef,
  SecretSourceOptions,
  WatchOptions,
} from '@platform-sec/sensitive-string-secrets';

import { deriveSpec, formatFor, parseCiphertext } from './derive.js';
import type { DeriveOptions, SopsFormat, YamlParser } from './derive.js';
import { SopsError, checkVersion, decryptArgs, decryptContext, run } from './spawn.js';
import type { RunOptions, SpawnResult } from './spawn.js';

export interface SopsSecretSourceOptions extends SecretSourceOptions {
  /**
   * The age identity, as a credential.
   *
   * The value that unlocks everything else should not be the one plain string
   * in the configuration, which is the same self-reference the Vault package
   * makes for its client token. Omit it where the key backend is KMS: the
   * ambient cloud credentials do the work and this package holds one fewer
   * secret.
   */
  readonly ageKey?: SensitiveString<'credential'> | undefined;
  /** The binary. Defaults to `sops`, resolved on PATH. */
  readonly binary?: string | undefined;
  /** How long a decrypt may take before the child is killed. */
  readonly timeoutMs?: number | undefined;
  /**
   * Attach the binary's stderr to a failed decrypt's error. Defaults to true.
   *
   * A deliberate exception to the caution this row shows about provider error
   * text, and it rests on `sops` failing before it produces plaintext: a MAC or
   * key failure means nothing was decrypted. That is an assumption about
   * another tool's behaviour, so it is in the README's measurement table rather
   * than asserted, and this is the switch that exists in case it turns out
   * otherwise.
   */
  readonly includeStderr?: boolean | undefined;
  /** How the encrypted document is parsed for derivation. Defaults to the extension. */
  readonly format?: SopsFormat | undefined;
  /** A YAML parser, since `yaml` is an optional peer. */
  readonly yamlParse?: YamlParser | undefined;
  /** Promotions, demotions and the class an encrypted leaf gets. */
  readonly derive?: DeriveOptions | undefined;
  /** Environment for the child only, such as `AWS_PROFILE`. */
  readonly env?: Readonly<Record<string, string>> | undefined;
}

/**
 * SOPS documents.
 *
 * The only source in this row where the thing that unlocks the secret is itself
 * a secret this package handles, and the only one that runs another program.
 *
 * @example
 * ```ts
 * import { parse } from 'yaml';
 * import { SopsSecretSource } from '@platform-sec/sensitive-string-sops';
 *
 * const sops = new SopsSecretSource({ ageKey: ageIdentity, yamlParse: parse });
 *
 * const secrets = await sops.getAll('/etc/app/secrets.enc.yaml');
 * secrets.fields.get('database.password');
 * secrets.plain.get('database.host');   // never encrypted in the file, so never wrapped
 * ```
 */
/** Whether a path is there at all, which is what an absence really is. */
async function exists(path: string): Promise<boolean> {
  try {
    await access(path);

    return true;
  } catch {
    return false;
  }
}

export class SopsSecretSource extends BaseSecretSource {
  protected readonly sourceName = 'sops';

  readonly #binary: string;
  readonly #ageKey: SensitiveString<'credential'> | undefined;
  readonly #timeoutMs: number;
  readonly #includeStderr: boolean;
  readonly #format: SopsFormat | undefined;
  readonly #yamlParse: YamlParser | undefined;
  readonly #derive: DeriveOptions;
  readonly #env: Readonly<Record<string, string>> | undefined;
  readonly #checked: Promise<string>;

  constructor(options: SopsSecretSourceOptions = {}) {
    super(options);

    this.#binary = options.binary ?? 'sops';
    this.#ageKey = options.ageKey;
    this.#timeoutMs = options.timeoutMs ?? 30_000;
    this.#includeStderr = options.includeStderr ?? true;
    this.#format = options.format;
    this.#yamlParse = options.yamlParse;
    this.#derive = options.derive ?? {};
    this.#env = options.env;

    // Started here so a missing binary fails where somebody can read it rather
    // than at the first decrypt in the middle of a request. The rejection is
    // parked until a decrypt awaits it, so an unhandled rejection does not take
    // the process down before anybody asked for a secret.
    this.#checked = checkVersion(this.#binary, this.#timeoutMs);
    this.#checked.catch(() => undefined);
  }

  /** The binary's version string, or the failure the constructor parked. */
  async version(): Promise<string> {
    return await this.#checked;
  }

  /** The file name. A directory path names a host layout and not a secret. */
  protected override deriveLabel(ref: SecretRef): string {
    return logicalLabel(basename(ref.path));
  }

  protected async fetchSecret(ref: SecretRef): Promise<ProviderResult | null> {
    await this.#checked;

    const resolved: ResolvedSecretRef = {
      path: this.deriveLabel(ref),
      version: 'decrypted',
      metadata: { file: ref.path },
    };

    let result: SpawnResult;

    try {
      result = await run(this.#runOptions(decryptArgs(ref.path)));
    } catch (error) {
      // `spawn` itself failed, which after the version check means the binary
      // went away or could not be executed. Not an absence.
      throw new SopsError(
        `Running '${this.#binary}' to decrypt '${resolved.path}' failed.`,
        resolved.path,
        error instanceof Error ? error.message : undefined
      );
    }

    if (result.code !== 0) {
      // An absent file is an absence rather than a failure, and the check is
      // the filesystem's rather than the binary's message. sops 3.13.3 says
      // `cannot operate on non-existent file "<path>"` and exits 100; an
      // earlier version of this package matched on `no such file or directory`
      // because that is what its own stand-in binary printed, so `getOptional`
      // threw for every absent document. The message match stays as a second
      // chance for a build that words it differently, and the stat is what the
      // behaviour actually rests on.
      if (!(await exists(ref.path))) {
        return null;
      }

      if (/non-existent file|no such file or directory|cannot find the file/i.test(result.stderr)) {
        return null;
      }

      throw new SopsError(
        `Decrypting '${resolved.path}' failed with exit code ${String(result.code)}. A ` +
          `decrypt failure is almost always a key or configuration problem.`,
        resolved.path,
        this.#includeStderr ? result.stderr.trim() : undefined
      );
    }

    // `--output-type json`, so the plaintext goes through the shared guard and
    // never near a YAML parser.
    const payload = parsePayload(result.stdout, resolved);

    return { payload: { kind: 'map', value: payload }, ref: resolved };
  }

  /**
   * Read a document, classifying each key the way SOPS encrypted it.
   *
   * This is the call the package is for. `getAll` with an explicit spec is
   * still available and turns the derivation off, which is why `fallback` is
   * required there and not here.
   */
  async getDerived(
    ref: SecretRef | string,
    options: Partial<GetAllOptions> = {}
  ): Promise<MultiSecretRecord> {
    const normalized = typeof ref === 'string' ? { path: ref } : ref;
    const spec = await this.deriveFor(normalized.path);

    return await this.getAll(normalized, {
      ...options,
      ...(spec.fields === undefined ? {} : { fields: { ...spec.fields, ...options.fields } }),
      ...(spec.rules === undefined ? {} : { rules: spec.rules }),
      fallback: options.fallback ?? spec.fallback ?? 'credential',
    });
  }

  /**
   * The classification a document's ciphertext implies.
   *
   * Exported as its own method because it is worth being able to look at: an
   * operator who left a genuine secret unencrypted in the file gets it
   * classified `plain`, which is a true report of what the file says and an
   * argument for a lint rule rather than for a different default.
   */
  async deriveFor(path: string): Promise<ClassificationSpec> {
    const ref: ResolvedSecretRef = {
      path: logicalLabel(basename(path)),
      version: 'ciphertext',
      metadata: {},
    };

    let source: string;

    try {
      source = await readFile(path, 'utf8');
    } catch {
      throw new SecretPayloadError(
        `The encrypted document '${ref.path}' could not be read, so its classification ` +
          `cannot be derived.`,
        ref.path,
        ref.version
      );
    }

    const document = parseCiphertext(source, this.#format ?? formatFor(path), ref, this.#yamlParse);

    return deriveSpec(document, this.#derive);
  }

  /**
   * Re-read the document when a deployment replaces it.
   *
   * A re-read is a full decrypt, so the debounce matters more here than
   * anywhere else: an undebounced watcher on a file replaced by rename spawns
   * several `sops` processes for one change.
   */
  watch(
    ref: SecretRef | string,
    options: Partial<GetAllOptions>,
    watchOptions: WatchOptions<MultiSecretRecord>
  ): FileWatcher {
    const normalized = typeof ref === 'string' ? { path: ref } : ref;

    return watchFile(
      normalized.path,
      async () => {
        this.refresh(normalized);

        return await this.getDerived(normalized, options);
      },
      watchOptions
    );
  }

  #runOptions(args: readonly string[]): RunOptions {
    return {
      binary: this.#binary,
      args,
      ageKey: this.#ageKey,
      context: decryptContext(),
      timeoutMs: this.#timeoutMs,
      env: this.#env,
    };
  }
}
