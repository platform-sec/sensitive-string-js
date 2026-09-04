import { probeKeys, probeProperty } from './probe.js';
import type { SensitiveFieldConfig } from '@platform-sec/sensitive-string-core';

/**
 * The convict read-side recipe's one piece of code.
 *
 * convict gets no package. Its `addFormat` coercion runs, and `config.get()`
 * then returns a `lodash.clonedeep` of the stored value: a new object with the
 * same prototype and the own enumerable properties copied, which means `klass`
 * and `label` survive, `instanceof` still passes, and every private field is
 * gone. `reveal()`, `toString()` and `util.inspect()` all throw
 * `TypeError: Receiver must be an instance of class SensitiveString`, so the
 * redaction path is the one that crashes, and `containsSensitive` reports the
 * clone as protected when it is neither usable nor redactable.
 *
 * So wrapping happens after the library rather than inside it, and the only
 * thing left for this package to do is check the schema.
 */

/**
 * Check a convict schema declares `sensitive: true` for every classified path.
 *
 * Structural, with no convict import: the schema is a plain nested object
 * whose leaves carry `default`, `format` and friends, so walking it needs
 * nothing from the library.
 *
 * It exists for the one thing convict's flag genuinely buys. `sensitive: true`
 * masks `config.toString()` and suppresses the value in a failed
 * `config.validate()` message, which otherwise appends `: value was "..."`.
 * It does not protect `config.get()`, `config.getProperties()`,
 * `util.inspect(config)` or `JSON.stringify(config)`, so the flag is a
 * complement to wrapping and never a replacement for it.
 *
 * Belongs in a test rather than at startup.
 *
 * @throws Error listing the paths that are missing from the schema or missing
 *   the flag. Never a value.
 */
export function assertSensitiveFlags(schema: unknown, config: SensitiveFieldConfig): void {
  const missingFromSchema: string[] = [];
  const missingFlag: string[] = [];

  for (const path of Object.keys(config)) {
    const node = resolveSchemaNode(schema, path);

    if (node === undefined) {
      missingFromSchema.push(path);
      continue;
    }

    if (probeProperty(node, 'sensitive') !== true) {
      missingFlag.push(path);
    }
  }

  if (missingFromSchema.length === 0 && missingFlag.length === 0) {
    return;
  }

  const parts: string[] = [];
  if (missingFromSchema.length > 0) {
    parts.push(`absent from the schema: ${missingFromSchema.join(', ')}`);
  }
  if (missingFlag.length > 0) {
    parts.push(`declared without \`sensitive: true\`: ${missingFlag.join(', ')}`);
  }

  throw new Error(`Classified convict paths ${parts.join('; ')}.`);
}

/** The schema node at a dot path, or `undefined`, without trusting the object. */
function resolveSchemaNode(schema: unknown, path: string): object | undefined {
  let current: unknown = schema;

  for (const part of path.split('.')) {
    if (part === '__proto__' || part === 'constructor' || part === 'prototype') {
      return undefined;
    }
    if (current === null || typeof current !== 'object') {
      return undefined;
    }
    if (!probeKeys(current).includes(part)) {
      return undefined;
    }
    current = probeProperty(current, part);
  }

  return current !== null && typeof current === 'object' ? current : undefined;
}
