import { SensitiveString } from '@platform-sec/sensitive-string-core';
import type { SensitivityClass } from '@platform-sec/sensitive-string-core';
import { describeType } from './describe-type.js';

/**
 * A `pretty-format` plugin, declared structurally.
 *
 * This is the shape of `pretty-format`'s `NewPlugin`, written out here so the
 * package keeps its rule that nothing in it depends on a test framework. The
 * serializer is handed to Vitest's or Jest's `expect.addSnapshotSerializer`,
 * both of which type that parameter as `NewPlugin`, and a structural match is
 * what lets one object satisfy both without importing either.
 *
 * `pretty-format` passes `serialize` five more arguments: the print config, the
 * current indentation, the depth, the values already visited, and a printer for
 * children. This serializer needs none of them, because it renders a leaf: it
 * never prints a child and never recurses, so there is nothing to indent, no
 * depth to track, and no cycle to break. They are declared as optional
 * `unknown` rather than imported so no `pretty-format` version pins this
 * package.
 */
export interface SnapshotSerializerPlugin {
  /** Whether this plugin renders the value. Called for every value printed. */
  test(value: unknown): boolean;
  /** The rendering. Called only for values `test` accepted. */
  serialize(
    value: unknown,
    config?: unknown,
    indentation?: string,
    depth?: number,
    refs?: unknown,
    printer?: unknown
  ): string;
}

/** Options for {@link createSensitiveSerializer}. */
export interface SensitiveSerializerOptions {
  /**
   * Add `{expired}` to the default format, so a value whose deadline has passed
   * renders as `SensitiveString<credential:otp:EXPIRED>`.
   *
   * Off by default, and worth leaving off for a stored snapshot: whether a
   * value is expired depends on when the test ran, so a snapshot that records
   * it holds only while the deadline stays on the same side of the clock. It
   * earns its place in an inline snapshot of a value built with `ttl: 0`, which
   * is expired at construction and stays that way.
   *
   * @defaultValue false
   */
  readonly showExpiration?: boolean;

  /**
   * Add `{length}` to the default format, so a value renders as
   * `SensitiveString<credential:api_key:len=32>`.
   *
   * Off by default. The length is not the value, and core treats it as
   * metadata, but a snapshot is committed to version control and the length of
   * a credential says more about it than its class and label do.
   *
   * @defaultValue false
   */
  readonly showLength?: boolean;

  /**
   * The rendering, with `{class}`, `{label}`, `{length}` and `{expired}` as
   * placeholders. There is deliberately no placeholder for the value.
   *
   * Each placeholder carries its own separator, so a format is a template for
   * the whole rendering rather than a list of fields to join: `{label}` expands
   * to `:api_key` or to nothing, and the three optional placeholders collapse
   * cleanly on a value with no label, no length shown and no deadline.
   *
   * A format supersedes `showLength` and `showExpiration`: the placeholders
   * written here decide what appears, so the two ways of asking for a field
   * cannot disagree. An unknown placeholder is rejected rather than passed
   * through, so a `{value}` someone expected to work fails at registration
   * instead of printing itself into every snapshot in the suite.
   *
   * @defaultValue `'SensitiveString<{class}{label}>'`, plus `{length}` and
   * `{expired}` when the options above ask for them
   */
  readonly format?: string;
}

/** The placeholders a format may contain. */
const PLACEHOLDERS = ['class', 'label', 'length', 'expired'] as const;

type Placeholder = (typeof PLACEHOLDERS)[number];

/** Matches one `{placeholder}`, and nothing that merely looks like one. */
const PLACEHOLDER_PATTERN = /\{([a-z]+)\}/g;

/**
 * Control characters, which a label must not carry into the rendering.
 *
 * Matching them is the point, so `no-control-regex` has nothing to warn about
 * here: the rule guards against a control character reaching a pattern by
 * accident, and this one is looking for them.
 */
// eslint-disable-next-line no-control-regex
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/g;

/** The escapes worth reading, for the control characters a label might hold. */
const CONTROL_ESCAPES: Readonly<Record<string, string>> = {
  '\b': '\\b',
  '\t': '\\t',
  '\n': '\\n',
  '\f': '\\f',
  '\r': '\\r',
};

/**
 * Build a snapshot serializer with a custom rendering.
 *
 * @param options - The format, and the fields to include.
 * @returns A plugin for `expect.addSnapshotSerializer` or for a runner's config.
 * @throws TypeError If an option has the wrong type, or the format names a placeholder that does not exist.
 *
 * @example
 * ```ts
 * const verbose = createSensitiveSerializer({ showLength: true, showExpiration: true });
 *
 * expect.addSnapshotSerializer(verbose);
 * // SensitiveString<credential:api_key:len=32>
 * // SensitiveString<credential:otp:len=6:EXPIRED>
 * ```
 */
export function createSensitiveSerializer(
  options: SensitiveSerializerOptions = {}
): SnapshotSerializerPlugin {
  // Resolved once, at registration, so a bad format is a loud failure in a
  // setup file rather than a failure inside the first snapshot that happens to
  // hold a sensitive value.
  const format = resolveFormat(options);

  return {
    test(value: unknown): boolean {
      return isSensitiveString(value);
    },

    serialize(value: unknown): string {
      if (!isSensitiveString(value)) {
        // Reachable only by calling the plugin directly, since `pretty-format`
        // calls `serialize` only for what `test` accepted. Naming the type is
        // safe; rendering the value would not be, because whatever arrived here
        // may be a raw copy of a secret.
        throw new TypeError(
          `The sensitive-string snapshot serializer received ${describeType(value)}, not a SensitiveString.`
        );
      }

      return render(format, value);
    },
  };
}

/**
 * A snapshot serializer for `SensitiveString`, with the default format.
 *
 * Register it once, in a setup file:
 *
 * ```ts
 * import { expect } from 'vitest';
 * import { sensitiveSerializer } from '@platform-sec/sensitive-string-testing';
 *
 * expect.addSnapshotSerializer(sensitiveSerializer);
 * ```
 *
 * A snapshot of a structure holding sensitive values then keeps the shape of
 * the structure and says what each sensitive field is, without recording what
 * it holds:
 *
 * ```
 * {
 *   "id": 1,
 *   "email": SensitiveString<sensitive:email>,
 *   "apiKey": SensitiveString<credential:api_key>,
 * }
 * ```
 *
 * The rendering is built from the class and the label, which are public
 * metadata, and never from the value: nothing here calls `reveal()`, and no
 * format placeholder prints a value. It also does not use the class policy's
 * `redact()`, so a project that registered a custom redaction format gets the
 * same snapshots as one that did not, and a policy registered with
 * `skipRedactValidation` cannot route a value into a snapshot through it.
 */
export const sensitiveSerializer: SnapshotSerializerPlugin = createSensitiveSerializer();

/**
 * The plugin again, as a default export, for a runner that loads it by path
 * rather than by importing it:
 *
 * ```js
 * // jest.config.js
 * module.exports = {
 *   snapshotSerializers: ['@platform-sec/sensitive-string-testing/serializer'],
 * };
 * ```
 *
 * That path is loaded with `require`, which is what this export is for. Code
 * that imports the module should use the named `sensitiveSerializer` instead:
 * this package builds to CommonJS, and a default import of a CommonJS module
 * from ES module code yields the module's exports rather than this value.
 */
export default sensitiveSerializer;

/**
 * The format to render with, after checking the options.
 *
 * `showLength` and `showExpiration` are shorthand for adding a placeholder to
 * the default format, so they have nothing to say once a format is given.
 */
function resolveFormat(options: SensitiveSerializerOptions): string {
  const { showExpiration = false, showLength = false, format } = options;

  checkBoolean(showExpiration, 'showExpiration');
  checkBoolean(showLength, 'showLength');

  if (format === undefined) {
    return [
      'SensitiveString<{class}{label}',
      showLength ? '{length}' : '',
      showExpiration ? '{expired}' : '',
      '>',
    ].join('');
  }

  if (typeof format !== 'string') {
    throw new TypeError(`format must be a string, but got ${describeType(format)}.`);
  }

  for (const match of format.matchAll(PLACEHOLDER_PATTERN)) {
    const name = match[1];

    if (name !== undefined && !isPlaceholder(name)) {
      throw new TypeError(
        [
          `format contains an unknown placeholder '{${name}}'. `,
          `The known placeholders are ${PLACEHOLDERS.map((known) => `{${known}}`).join(', ')}. `,
          'There is none for the value: a snapshot is committed to version control, ',
          'so the serializer has no way to print one.',
        ].join('')
      );
    }
  }

  return format;
}

/**
 * Expand the placeholders in one pass.
 *
 * One pass with a replacement function, rather than a `replace` per
 * placeholder, for two reasons. A label is arbitrary text, so a label of
 * `{class}`, or one holding `$&`, would otherwise be expanded by a later pass
 * or read as a replacement pattern. And a format may name a placeholder twice,
 * which a `String.prototype.replace` per placeholder would honour only the
 * first time.
 */
function render(format: string, value: SensitiveString<SensitivityClass>): string {
  return format.replace(PLACEHOLDER_PATTERN, (whole: string, name: string) =>
    isPlaceholder(name) ? expand(name, value) : whole
  );
}

function expand(placeholder: Placeholder, value: SensitiveString<SensitivityClass>): string {
  switch (placeholder) {
    case 'class':
      return value.klass;
    case 'label':
      return value.label === undefined ? '' : `:${escapeLabel(value.label)}`;
    case 'length':
      return `:len=${value.length}`;
    case 'expired':
      // `ttlRemaining()` rather than `isExpired()`, which asks the same question
      // without the side effect: the first `isExpired()` on a lapsed value fires
      // the `onExpire` callback of every source it derives from. Printing a
      // snapshot must not be what triggers an expiry hook, and a snapshot that
      // is printed twice must not fire it twice.
      return value.ttlRemaining() === -1 ? ':EXPIRED' : '';
  }
}

/**
 * A label with its control characters escaped.
 *
 * A label is developer-supplied text rather than a value, so it prints as it
 * stands. A newline or a tab in one would break the line being rendered into
 * and silently corrupt the indentation of the whole snapshot, so those become
 * escapes. Everything printable is left alone, including a `{`, which cannot be
 * re-expanded because the format expands in a single pass.
 */
function escapeLabel(label: string): string {
  return label.replace(
    CONTROL_CHARACTERS,
    (character: string) =>
      CONTROL_ESCAPES[character] ?? `\\x${character.charCodeAt(0).toString(16).padStart(2, '0')}`
  );
}

/**
 * Whether the value is a `SensitiveString`, as a predicate rather than a bare
 * `instanceof`.
 *
 * `instanceof SensitiveString` narrows to `SensitiveString<any>`, because the
 * class is generic in its sensitivity class and the check says nothing about
 * which one. The predicate names the union instead, so nothing downstream of
 * the narrowing is typed `any`.
 */
function isSensitiveString(value: unknown): value is SensitiveString<SensitivityClass> {
  return value instanceof SensitiveString;
}

function isPlaceholder(name: string): name is Placeholder {
  return (PLACEHOLDERS as readonly string[]).includes(name);
}

function checkBoolean(value: unknown, name: string): void {
  if (typeof value !== 'boolean') {
    throw new TypeError(`${name} must be a boolean, but got ${describeType(value)}.`);
  }
}
