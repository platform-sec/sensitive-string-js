import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { getGlobalSingleton } from './global-state.js';
import { SensitiveStringError } from './errors.js';

/**
 * Holding the value as ciphertext instead of as a string, and what that is
 * worth, which is narrower and stranger than the phrase suggests.
 *
 * The key is in the same process as the ciphertext. Nothing here survives the
 * process, nothing here protects a value the process is currently using, and
 * this is not encryption at rest. State that first, because the name invites
 * the opposite reading.
 *
 * Encryption is also not what keeps the plaintext out of a heap snapshot. A
 * `Buffer`'s bytes are external to the V8 heap and a snapshot never records
 * them, so `Buffer.from(value)` achieves that on its own with no key involved.
 * What the key adds is three things a plain buffer cannot do:
 *
 * - Zeroing 32 bytes makes every sealed value in the process permanently
 *   unreadable, in constant time, with no registry of instances to walk and no
 *   way for an instance to be missed. `clearAllSensitiveValues()` needs an
 *   opt-in `WeakRef` registry whose pruning lags collection, and it reaches
 *   only what it tracked.
 * - The resident bytes are not the value. A disclosure channel that carries
 *   bytes rather than the class's redacted rendering, a buffer written to a
 *   log or serialized by a crash reporter, carries ciphertext.
 * - The stored form is bytes, so `clear()` can zero it and `equals()` can
 *   compare without materializing a string. Strings can do neither, ever.
 *
 * The cost is real and is stated on the `sealed` option: a read runs a cipher
 * where an unsealed one reads a field, and every string-returning reveal leaves
 * one copy of the plaintext in process memory that garbage collection does not
 * remove. `revealBytes()` and `equals()` are the paths that leave nothing, and
 * a value read repeatedly should use them. `__benchmarks__/sealing.bench.ts`
 * prices each shape against its unsealed twin.
 */

/** AES-256-GCM: 32-byte key, 96-bit IV, 128-bit tag. */
const KEY_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const GENERATION_BYTES = 4;

/** The smallest well-formed box: a header, an IV, no ciphertext, and a tag. */
const MIN_BOX_BYTES = GENERATION_BYTES + IV_BYTES + TAG_BYTES;

/**
 * Seals allowed under one key before a new generation is started.
 *
 * NIST SP 800-38D section 8.3 puts the limit on random 96-bit IVs under a
 * fixed key at 2^32 invocations. At the measured seal rate a process sealing
 * continuously reaches it in under nine hours, which is not a theoretical
 * bound for a long-lived service, so it is enforced rather than noted.
 */
const DEFAULT_SEAL_BUDGET = 2 ** 32;

/**
 * Generations the ring may hold, bounded by what the box header can address.
 *
 * With the budget above this is 2^64 seals before sealing stops being
 * available. It will not be reached; the bound exists so the failure is a
 * named error rather than a silently truncated generation index.
 */
const DEFAULT_MAX_GENERATIONS = 0xffffffff + 1;

/**
 * Raised when `sealed: true` was asked for and this process cannot seal.
 *
 * One reason today. It is a class rather than a boolean because the reason is
 * what a caller would act on, and because a second reason would otherwise
 * arrive as a message change.
 */
export class SealingUnavailableError extends SensitiveStringError {
  override readonly name = 'SealingUnavailableError';
  override readonly code = 'sealing-unavailable';

  constructor(
    readonly reason: 'generations-exhausted',
    readonly label?: string
  ) {
    super(
      `Cannot seal sensitive value${label !== undefined ? ` '${label}'` : ''}: ` +
        `sealing is unavailable (${reason})`
    );
  }
}

/**
 * Raised when the generation a value was sealed under has been destroyed.
 *
 * Distinguished from {@link SealedValueIntegrityError} so a caller can tell an
 * incident-response key destruction from a tampered box. Generation indices are
 * never reused within a process, so the ring can always tell the two apart.
 */
export class SealingKeyDestroyedError extends SensitiveStringError {
  override readonly name = 'SealingKeyDestroyedError';
  override readonly code = 'sealing-key-destroyed';

  constructor(
    readonly destroyedAt: Date,
    readonly attemptedAt: Date,
    readonly label?: string
  ) {
    super(
      `Sealing key for sensitive value${label !== undefined ? ` '${label}'` : ''} was ` +
        `destroyed at ${destroyedAt.toISOString()}`
    );
  }

  /** Milliseconds between the destruction and the attempted access. */
  get destroyedFor(): number {
    return this.attemptedAt.getTime() - this.destroyedAt.getTime();
  }
}

/**
 * Raised when a sealed value's box fails authentication.
 *
 * In practice this means the instance was tampered with. `klass` and `label`
 * are bound into the GCM additional data, so rewriting either makes the value
 * unreadable rather than reclassified: the runtime write that downgrades a
 * credential to a class with weaker redaction and no constant-time comparison
 * succeeds on an unsealed value and fails closed here.
 *
 * It deliberately does not carry OpenSSL's message. Node's is "Unsupported
 * state or unable to authenticate data", which says nothing useful, and a
 * runtime's own diagnostic is not something a security wrapper should re-raise
 * unread.
 */
export class SealedValueIntegrityError extends SensitiveStringError {
  override readonly name = 'SealedValueIntegrityError';
  override readonly code = 'sealed-value-integrity';

  constructor(readonly label?: string) {
    super(
      `Sealed sensitive value${label !== undefined ? ` '${label}'` : ''} failed ` +
        `authentication: the stored box, its class or its label was modified`
    );
  }
}

/**
 * Process-global sealing settings.
 *
 * Read at construction, so a value built before {@link setSealing} runs is not
 * sealed. Configure this alongside policy registration in the process's entry
 * module, before anything wraps a secret.
 */
export interface SealingConfig {
  /**
   * Seal values constructed without an explicit `sealed` option.
   *
   * Off by default, and it should stay off for most processes: section 12 of
   * the design names the shape worth sealing, which is a credential loaded once
   * at startup and held for the life of the process, not a value wrapped per
   * request. The packages that produce the first shape, `secrets`, `vault`,
   * `env` and the config loaders, are where this belongs.
   *
   * Default `false`.
   */
  sealByDefault?: boolean;

  /**
   * Refuse to construct a sealed value when sealing is unavailable, rather than
   * falling back to a plaintext string.
   *
   * Default `true`: a silent downgrade to the representation the caller was
   * trying to avoid is the wrong failure.
   */
  strict?: boolean;
}

/**
 * Every switch resolved, which is what the singleton holds.
 *
 * Module-private, and `getSealing` spells its return type out rather than
 * naming it: a consumer reading the declaration should see the shape, not an
 * alias it cannot import.
 */
type ResolvedSealing = Readonly<Required<SealingConfig>>;

const DEFAULTS: ResolvedSealing = Object.freeze({
  sealByDefault: false,
  strict: true,
});

/**
 * One key and its use, plus the tombstone a destroy leaves behind.
 *
 * `index` is carried rather than derived from the array position so the seal
 * path allocates nothing to report which key it used.
 */
interface Generation {
  readonly index: number;
  readonly key: Buffer;
  seals: number;
  destroyed: Date | undefined;
}

interface SealingGlobals {
  config: ResolvedSealing;
  /**
   * Every key this process has generated, in order, including destroyed ones.
   *
   * Destroyed generations stay as tombstones so their indices are never
   * reused: that is what lets a box whose key is gone report a destruction
   * rather than an integrity failure.
   */
  generations: Generation[];
  /** Seals allowed per generation. Lowered only by the test-only hook. */
  budget: number;
  /** Generations the ring may hold. Lowered only by the test-only hook. */
  maxGenerations: number;
}

/**
 * The one ring and configuration every physical copy of core shares.
 *
 * Exported for `sensitive-string.ts`, which reads `config` on the construction
 * path: one property chain rather than a call through an accessor, which is
 * what a process that never seals anything pays for the feature.
 *
 * @internal
 */
export const sealing = getGlobalSingleton<SealingGlobals>('memory-sealing', () => ({
  config: DEFAULTS,
  generations: [],
  budget: DEFAULT_SEAL_BUDGET,
  maxGenerations: DEFAULT_MAX_GENERATIONS,
}));

/**
 * The generation to seal under, starting a new one when the current is spent
 * or destroyed.
 *
 * Charges the seal here rather than after the cipher runs, so a `createCipheriv`
 * that throws cannot leave a nonce budget uncharged for an IV that was drawn.
 */
function currentGeneration(label: string | undefined): Generation {
  const ring = sealing.generations;
  const last = ring.length === 0 ? undefined : ring[ring.length - 1];

  if (last !== undefined && last.destroyed === undefined && last.seals < sealing.budget) {
    last.seals += 1;
    return last;
  }

  if (ring.length >= sealing.maxGenerations) {
    throw new SealingUnavailableError('generations-exhausted', label);
  }

  const next: Generation = {
    index: ring.length,
    key: randomBytes(KEY_BYTES),
    seals: 1,
    destroyed: undefined,
  };

  ring.push(next);
  return next;
}

/**
 * The GCM additional data binding a box to the instance's classification.
 *
 * `klass || 0x00 || present || label`. The discriminator byte is there because
 * a missing label and an empty one must not produce the same additional data,
 * which they would if the separator alone divided them.
 *
 * @internal
 */
export function additionalData(klass: string, label: string | undefined): Buffer {
  return Buffer.concat([
    Buffer.from(klass, 'utf8'),
    Buffer.from([0x00, label === undefined ? 0x00 : 0x01]),
    label === undefined ? Buffer.alloc(0) : Buffer.from(label, 'utf8'),
  ]);
}

/**
 * Encrypt bytes into a box: `generation || iv || ciphertext || tag`.
 *
 * The caller owns `plain` and decides when to zero it; this function reads it
 * and nothing else. 32 bytes of overhead, one allocation.
 *
 * @internal
 */
export function sealBytes(plain: Buffer, aad: Buffer, label: string | undefined): Buffer {
  const generation = currentGeneration(label);
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', generation.key, iv);
  cipher.setAAD(aad);

  const header = Buffer.alloc(GENERATION_BYTES);
  header.writeUInt32BE(generation.index, 0);

  // Evaluated left to right, which is the order GCM requires: the tag is only
  // available once `final()` has run.
  return Buffer.concat([header, iv, cipher.update(plain), cipher.final(), cipher.getAuthTag()]);
}

/**
 * Decrypt a box back into bytes the caller owns and may zero.
 *
 * Never returns a string. The two callers decide whether one is wanted, which
 * is the whole point of the split: `equals()` and `revealBytes()` never make
 * one, and section 2.3 of the design measures that as the difference between
 * leaving a thousand plaintext copies in process memory and leaving none.
 *
 * @internal
 */
export function openBox(box: Buffer, aad: Buffer, label: string | undefined): Buffer {
  if (box.length < MIN_BOX_BYTES) {
    throw new SealedValueIntegrityError(label);
  }

  const generation = sealing.generations[box.readUInt32BE(0)];

  if (generation === undefined) {
    // A box from a ring this process no longer has, which `resetSealing()` is
    // the only way to produce. Reported as tampering rather than as a
    // destruction, because the key that would have opened it is not merely
    // zeroed: there is no record that it ever existed.
    throw new SealedValueIntegrityError(label);
  }

  if (generation.destroyed !== undefined) {
    throw new SealingKeyDestroyedError(generation.destroyed, new Date(), label);
  }

  // GCM produces plaintext before it verifies the tag, so this holds real bytes
  // even on the path that is about to be refused. It is tracked from here so
  // the `finally` can zero it, and released to `undefined` at the one point
  // where it becomes the caller's to own.
  let unauthenticated: Buffer | undefined;

  try {
    const decipher = createDecipheriv(
      'aes-256-gcm',
      generation.key,
      box.subarray(GENERATION_BYTES, GENERATION_BYTES + IV_BYTES)
    );
    decipher.setAAD(aad);
    decipher.setAuthTag(box.subarray(box.length - TAG_BYTES));

    unauthenticated = decipher.update(
      box.subarray(GENERATION_BYTES + IV_BYTES, box.length - TAG_BYTES)
    );

    const tail = decipher.final();

    if (tail.length === 0) {
      // The ordinary path for GCM, which has no block padding: `update`
      // returned everything. Handing that buffer over directly is one fewer
      // copy of the plaintext than concatenating would leave behind.
      const opened = unauthenticated;
      unauthenticated = undefined;
      return opened;
    }

    const opened = Buffer.concat([unauthenticated, tail]);
    tail.fill(0);
    return opened;
  } catch {
    // Every failure in this block is reported the same way, and none of them
    // carries the runtime's own text. `final()` failing is the tag check and is
    // the expected one; anything else here is a malformed box that got past the
    // length guard, and OpenSSL's diagnostic for either says nothing a caller
    // can act on.
    throw new SealedValueIntegrityError(label);
  } finally {
    unauthenticated?.fill(0);
  }
}

/** Whether a byte is a UTF-8 continuation. */
function isContinuation(byte: number | undefined): boolean {
  return byte !== undefined && (byte & 0xc0) === 0x80;
}

function invalidUtf8(offset: number): TypeError {
  return new TypeError(
    `SensitiveString.fromBuffer expects valid UTF-8; the sequence at byte ${offset} is not`
  );
}

/**
 * Validate UTF-8 and count the UTF-16 code units it decodes to, in one walk.
 *
 * Both halves have to happen without decoding. `length` on a sealed value must
 * agree with `length` on an unsealed one, which is a code unit count, and the
 * obvious validator, `new TextDecoder('utf-8', { fatal: true }).decode(bytes)`,
 * produces exactly the plaintext string `fromBuffer` exists to avoid.
 *
 * Strict: overlong encodings, surrogate code points and anything above
 * U+10FFFF are refused rather than replaced. A lenient decoder would substitute
 * U+FFFD, which changes both the value a later `reveal()` returns and its
 * length, so a caller would get back something other than what it passed.
 *
 * @internal
 */
export function utf8CodeUnits(bytes: Buffer): number {
  let units = 0;
  let at = 0;

  while (at < bytes.length) {
    const lead = bytes[at]!;

    if (lead < 0x80) {
      at += 1;
      units += 1;
      continue;
    }

    // 0xc0 and 0xc1 can only encode a value below U+0080, which is overlong.
    if (lead >= 0xc2 && lead <= 0xdf) {
      if (!isContinuation(bytes[at + 1])) {
        throw invalidUtf8(at);
      }

      at += 2;
      units += 1;
      continue;
    }

    if (lead >= 0xe0 && lead <= 0xef) {
      // 0xe0 below 0xa0 is overlong; 0xed at 0xa0 or above is a surrogate.
      const low = lead === 0xe0 ? 0xa0 : 0x80;
      const high = lead === 0xed ? 0x9f : 0xbf;
      const second = bytes[at + 1];

      if (second === undefined || second < low || second > high) {
        throw invalidUtf8(at);
      }

      if (!isContinuation(bytes[at + 2])) {
        throw invalidUtf8(at);
      }

      at += 3;
      units += 1;
      continue;
    }

    if (lead >= 0xf0 && lead <= 0xf4) {
      // 0xf0 below 0x90 is overlong; 0xf4 at 0x90 or above is beyond U+10FFFF.
      const low = lead === 0xf0 ? 0x90 : 0x80;
      const high = lead === 0xf4 ? 0x8f : 0xbf;
      const second = bytes[at + 1];

      if (second === undefined || second < low || second > high) {
        throw invalidUtf8(at);
      }

      if (!isContinuation(bytes[at + 2]) || !isContinuation(bytes[at + 3])) {
        throw invalidUtf8(at);
      }

      at += 4;
      // Beyond the basic plane, so it decodes to a surrogate pair.
      units += 2;
      continue;
    }

    throw invalidUtf8(at);
  }

  return units;
}

function describeType(value: unknown): string {
  return value === null ? 'null' : typeof value;
}

function requireBoolean(value: unknown, name: string, fallback: boolean): boolean {
  if (value === undefined) {
    return fallback;
  }

  if (typeof value !== 'boolean') {
    throw new TypeError(`setSealing: ${name} must be a boolean, received ${describeType(value)}`);
  }

  return value;
}

/**
 * Configure sealing for this process. Merges: an unset field is left as it was.
 *
 * `sealByDefault` is read at construction, so this belongs in the entry module
 * beside `registerPolicy`, before anything wraps a value. A value built before
 * this call is not sealed, and there is no way to retrofit sealing onto it.
 *
 * Per-isolate, like every other process-global in this library: a worker thread
 * has its own `globalThis`, so its own configuration and its own keys. A box
 * cannot travel between isolates, and nothing tries to send one.
 *
 * @param config - The switches to change.
 * @throws TypeError If the configuration, or one of its fields, has the wrong type.
 *
 * @example
 * ```ts
 * setSealing({ sealByDefault: true });
 * ```
 */
export function setSealing(config: SealingConfig): void {
  if (typeof config !== 'object' || config === null) {
    throw new TypeError(
      `setSealing expects a configuration object; received ${describeType(config)}`
    );
  }

  const current = sealing.config;

  sealing.config = Object.freeze({
    sealByDefault: requireBoolean(config.sealByDefault, 'sealByDefault', current.sealByDefault),
    strict: requireBoolean(config.strict, 'strict', current.strict),
  });
}

/**
 * The configuration in force, with every default resolved.
 *
 * A frozen copy of the live object rather than the object itself, so a caller
 * cannot reconfigure the process by writing to what it reads back. The result
 * is accepted by {@link setSealing}, so it can be saved and restored.
 */
export function getSealing(): Readonly<Required<SealingConfig>> {
  const { sealByDefault, strict } = sealing.config;
  return Object.freeze({ sealByDefault, strict });
}

/**
 * Zero every sealing key this process holds.
 *
 * Every value sealed under them becomes permanently unreadable, including
 * values other libraries in this process constructed. Constant time, no
 * instance registry, and no instance can be missed, which is what this has
 * over {@link clearAllSensitiveValues}: that walks an opt-in `WeakRef` set
 * whose pruning lags collection and reaches only what it tracked.
 *
 * Values sealed after this call use a fresh generation and are unaffected, so
 * it is safe in a handler that runs while the process is still serving.
 *
 * What it does not reach: plaintext that earlier string-returning reveals left
 * in process memory, unsealed values, and the expanded key schedules OpenSSL
 * built in freed allocator memory during earlier operations. The last is a real
 * caveat rather than a formality: an AES key schedule is an expansion of the
 * key, not a copy of it, and recovering one from the other is arithmetic. The
 * claim this call supports is that no copy of the 32 key bytes remains, which
 * was measured; it is not that erasure is total.
 *
 * Idempotent. Produces no audit record, because it reads no value and has no
 * value to name in one: a process that wants a record of an incident-response
 * key destruction logs it at the call site, where the reason is known.
 *
 * @example
 * ```ts
 * process.on('SIGTERM', async () => {
 *   await server.close();     // stop accepting, drain what is in flight
 *   await pool.end();         // nothing still needs a credential
 *   destroySealingKey();      // every sealed value in the process is now dead
 * });
 * ```
 */
export function destroySealingKey(): void {
  const now = new Date();

  for (const generation of sealing.generations) {
    if (generation.destroyed === undefined) {
      generation.key.fill(0);
      generation.destroyed = now;
    }
  }
}

/**
 * Restore the defaults, zero every key and empty the ring.
 *
 * Test-only, and gated exactly as `resetPolicies()` is: it undoes process-wide
 * configuration, so a production caller reaching for it is describing a bug.
 *
 * One difference from {@link destroySealingKey} is worth knowing before a test
 * relies on it. Emptying the ring is the one thing in this module that reuses a
 * generation index, so a value sealed before the reset reports
 * {@link SealedValueIntegrityError} rather than {@link SealingKeyDestroyedError}
 * afterwards. Both refuse; only the second names what happened. A test that
 * wants the second must call `destroySealingKey()` instead.
 */
export function resetSealing(): void {
  sealing.config = DEFAULTS;

  for (const generation of sealing.generations) {
    generation.key.fill(0);
  }

  sealing.generations.length = 0;
  sealing.budget = DEFAULT_SEAL_BUDGET;
  sealing.maxGenerations = DEFAULT_MAX_GENERATIONS;
}

/**
 * Lower the nonce budget and the ring size so the generation machinery can be
 * driven in a test.
 *
 * Test-only, `@internal`, and deliberately absent from `index.ts`: crossing
 * 2^32 seals or 2^32 generations honestly takes hours and millennia
 * respectively, and a feature nothing can reach is a feature nothing has
 * checked. Neither limit may be raised above its default, because the budget
 * is a nonce-reuse bound rather than a tuning knob.
 *
 * Undone by {@link resetSealing}.
 *
 * @internal
 */
export function setSealingLimits(limits: { budget?: number; generations?: number }): void {
  if (limits.budget !== undefined) {
    if (!Number.isInteger(limits.budget) || limits.budget < 1) {
      throw new RangeError('setSealingLimits: budget must be a positive integer');
    }

    sealing.budget = Math.min(limits.budget, DEFAULT_SEAL_BUDGET);
  }

  if (limits.generations !== undefined) {
    if (!Number.isInteger(limits.generations) || limits.generations < 1) {
      throw new RangeError('setSealingLimits: generations must be a positive integer');
    }

    sealing.maxGenerations = Math.min(limits.generations, DEFAULT_MAX_GENERATIONS);
  }
}

/**
 * How many generations the ring holds, and how many seals the current one has
 * charged.
 *
 * Not part of the public surface: it reports the shape of the key ring, which
 * is an implementation detail everywhere except in the suite that measures the
 * generation rollover.
 *
 * @internal
 */
export function sealingRingState(): { generations: number; seals: number; destroyed: number } {
  const ring = sealing.generations;
  const last = ring.length === 0 ? undefined : ring[ring.length - 1];

  return {
    generations: ring.length,
    seals: last?.seals ?? 0,
    destroyed: ring.filter((generation) => generation.destroyed !== undefined).length,
  };
}
