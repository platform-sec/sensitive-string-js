import { redactInStructure, sensitiveClassesIn } from './redact.js';
import type { SensitivityClass } from './types.js';

/**
 * Winston stores the finished output string, the immutable level, and the raw
 * interpolation arguments under registry symbols. They are read through
 * Symbol.for() rather than by importing triple-beam, which is how this module
 * stays free of runtime dependencies. triple-beam defines them the same way.
 */
const MESSAGE = Symbol.for('message');
const SPLAT = Symbol.for('splat');

/**
 * Where this format records the sensitivity classes a record carried before it
 * was redacted.
 *
 * Redaction destroys the evidence a later `dropClasses` check needs: once an
 * instance has become the string `[REDACTED:credential]`, nothing downstream
 * can tell what class it was. Stamping the classes keeps per-transport policy
 * working behind a logger-level redaction. The key is symbol-based, so it never
 * reaches a serializer, and namespaced, so duplicate installations of this
 * package agree on it.
 */
const CLASSES = Symbol.for('@platform-sec/sensitive-string-core/classes');

/**
 * A winston log record.
 *
 * Symbol-keyed entries carry the level, the finished output string, and the
 * splat arguments. They are not expressible in an interface, which is precisely
 * why {@link sensitiveFormat} preserves the record by identity instead of
 * rebuilding it.
 */
export interface WinstonInfo {
  level: string;
  message: unknown;
  [key: string | symbol]: unknown;
}

/**
 * The shape winston and logform require of a format.
 *
 * Declared structurally so that this package keeps zero runtime dependencies:
 * `format.combine()` validates only that each entry owns a `transform`
 * function, so a plain object satisfies it.
 */
export interface WinstonFormat {
  transform(info: WinstonInfo, opts?: unknown): WinstonInfo | false;
  options?: object;
}

/**
 * Options for {@link sensitiveFormat}.
 */
export interface SensitiveFormatOptions {
  /**
   * Sensitivity classes whose presence discards the whole record instead of
   * redacting it. Empty by default.
   *
   * This is the one operation that still works when the format is installed on
   * a transport, which makes it the way to express per-transport policy such as
   * "the debug sink never receives a record carrying a credential".
   */
  dropClasses?: readonly SensitivityClass[];

  /**
   * Also redact the raw argument array winston keeps under
   * `Symbol.for('splat')`. Defaults to true.
   *
   * Interpolation is already safe, because `util.format` reaches values through
   * `toString`, `toJSON`, or the inspect hook. This closes the remaining path
   * where a custom format reads the splat array and serializes it itself.
   */
  redactSplat?: boolean;

  /**
   * Record which sensitivity classes the record carried, so that a `dropClasses`
   * check further down the pipeline still works after redaction has replaced the
   * instances with strings. Defaults to false.
   *
   * Set it on the logger-level format when a transport-level format uses
   * `dropClasses`. It costs one extra traversal per record, which is why it is
   * not on by default. Setting `dropClasses` implies it, since that check
   * already computes the classes.
   */
  stampClasses?: boolean;

  /**
   * Emit a process warning the first time the format runs after a terminal
   * format has already built `Symbol.for('message')`, where redaction cannot
   * affect the output. Defaults to true.
   *
   * Not emitted when `dropClasses` is set, because dropping is exactly the
   * operation that still works in that position.
   */
  warnOnLateInstall?: boolean;

  /**
   * Called when redaction throws. The record is still emitted, scrubbed.
   *
   * The error is passed through untouched, so a handler that logs it must
   * treat it as potentially carrying sensitive data.
   */
  onError?: (error: unknown) => void;
}

const SCRUBBED_MESSAGE = '[sensitive-format-error]';

const LATE_INSTALL_WARNING =
  'sensitiveFormat() ran after the output string was already built, so redaction ' +
  'cannot affect it. Move it to the front of format.combine(). Dropping by class ' +
  'still works in this position.';

/**
 * Redact every SensitiveString in a winston record before a terminal format or
 * a transport serializes it.
 *
 * Winston is already safe for the paths it controls, because SensitiveString
 * overrides `toString()`, `toJSON()`, and the Node inspect hook. This format
 * exists for the paths it does not control: transports that walk own enumerable
 * properties, or hand the record to a BSON or protobuf encoder, or pass it
 * through `structuredClone`, none of which call `toJSON()`. It also normalizes
 * the redacted text, so two transports on one logger record a field the same
 * way.
 *
 * Install it at the FRONT of `format.combine(...)`. In any later position the
 * output string already exists and redaction has no effect on what is written.
 *
 * @param options - Redaction and policy options
 * @returns A format object accepted by `winston.format.combine()` and by the
 *   `format` option of a logger or a transport
 *
 * @example
 * ```ts
 * const logger = winston.createLogger({
 *   format: winston.format.combine(sensitiveFormat(), winston.format.json()),
 *   transports: [new winston.transports.Console()],
 * });
 * ```
 *
 * @example
 * ```ts
 * // Per-transport policy: this sink refuses credential-bearing records
 * // outright, while other transports still receive them redacted.
 * new winston.transports.File({
 *   filename: 'debug.log',
 *   format: sensitiveFormat({ dropClasses: ['credential'] }),
 * });
 * ```
 */
export function sensitiveFormat(options: SensitiveFormatOptions = {}): WinstonFormat {
  const {
    dropClasses = [],
    redactSplat = true,
    stampClasses = false,
    warnOnLateInstall = true,
    onError,
  } = options;

  const collectClasses = stampClasses || dropClasses.length > 0;

  let warned = false;

  return {
    options,

    transform(info: WinstonInfo): WinstonInfo | false {
      try {
        if (warnOnLateInstall && !warned && dropClasses.length === 0 && MESSAGE in info) {
          warned = true;
          process.emitWarning(LATE_INSTALL_WARNING, 'SensitiveStringWarning');
        }

        if (collectClasses) {
          const present = classesInRecord(info);

          if (dropClasses.some((klass) => present.has(klass))) {
            return false;
          }

          info[CLASSES] = present;
        }

        // Assign redacted copies onto the record, which winston creates per
        // call and owns. Never recurse into it in place: winston merges
        // caller-supplied meta shallowly, so every nested object is still
        // shared with the caller and with the other transports.
        for (const key of Object.keys(info)) {
          // `level` is winston's severity string and is never sensitive.
          // Skipping it also keeps its declared string type intact.
          if (key !== 'level') {
            info[key] = redactInStructure(info[key]);
          }
        }

        if (redactSplat) {
          const splat: unknown = info[SPLAT];
          if (Array.isArray(splat)) {
            info[SPLAT] = (splat as unknown[]).map((arg) => redactInStructure(arg));
          }
        }

        return info;
      } catch (error) {
        onError?.(error);
        return scrub(info);
      }
    },
  };
}

/**
 * Every sensitivity class this record carries.
 *
 * The union of three sources, because a class missed here is a record that
 * `dropClasses` fails to refuse: the record's own fields, the interpolation
 * arguments under `Symbol.for('splat')`, where `logger.info('%s', secret)` puts
 * a value that never becomes a field, and the stamp left by an upstream format
 * that already redacted the instances away.
 */
function classesInRecord(info: WinstonInfo): Set<SensitivityClass> {
  // Unioned here rather than by handing one accumulator to both walks: the
  // accumulator is not part of `sensitiveClassesIn`'s signature, because a
  // caller who primes it gets back a set naming a class the payload does not
  // hold. The two walks were already independent, sharing no `seen`.
  const found = new Set<SensitivityClass>(readStamp(info));

  for (const klass of sensitiveClassesIn(info)) {
    found.add(klass);
  }

  const splat: unknown = info[SPLAT];
  if (Array.isArray(splat)) {
    for (const klass of sensitiveClassesIn(splat)) {
      found.add(klass);
    }
  }

  return found;
}

/**
 * Read the classes an upstream format stamped on the record.
 *
 * Anything other than a Set is ignored rather than trusted: the key is a
 * registry symbol, so another package could in principle have written it.
 */
function readStamp(info: WinstonInfo): ReadonlySet<SensitivityClass> {
  const stamped: unknown = info[CLASSES];
  return stamped instanceof Set ? (stamped as Set<SensitivityClass>) : new Set();
}

/**
 * Fail closed after a redaction error.
 *
 * The record is kept, because dropping it would remove evidence that something
 * happened, and stripped, because passing it through would emit the fields
 * redaction did not finish processing. The symbol-keyed entries survive, so the
 * record still routes and still counts.
 */
function scrub(info: WinstonInfo): WinstonInfo {
  for (const key of Object.keys(info)) {
    if (key !== 'level') {
      delete info[key];
    }
  }
  info['message'] = SCRUBBED_MESSAGE;

  // A transport writes Symbol.for('message'), not the record's fields. When it
  // already holds output built upstream, clearing the fields alone changes
  // nothing that gets written, and the scrub would be silently cosmetic.
  if (MESSAGE in info) {
    info[MESSAGE] = SCRUBBED_MESSAGE;
  }

  return info;
}
