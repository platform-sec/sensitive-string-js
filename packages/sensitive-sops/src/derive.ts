/**
 * Classification derived from the ciphertext.
 *
 * SOPS already recorded which values are secret. An encrypted leaf is the
 * literal string `ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]`, and
 * anything SOPS left alone is a value somebody decided did not need encrypting.
 * Deriving the classification from that is better than asking the caller to
 * restate it, because a hand-written spec drifts from the file and the drift is
 * silent in the direction that matters: a newly encrypted field the spec does
 * not mention.
 *
 * The alternative source of the same information is `.sops.yaml`'s
 * `encrypted_regex`, `unencrypted_regex` and `encrypted_suffix`. Reading the
 * ciphertext is preferred because it is what was actually encrypted rather than
 * what the rules were supposed to encrypt, and the two disagree whenever the
 * rules changed after the file was written.
 *
 * **The parser that can leak never sees plaintext.** Deriving means reading the
 * encrypted file, which for the common case is YAML and needs a YAML parser,
 * and YAML parsers report the offending line in their errors. That is safe here
 * and only here: the encrypted file's values are ciphertext, so a parse error
 * on it discloses ciphertext and key names. The decrypted document is JSON and
 * goes through the shared guard. Keeping the YAML parser on the ciphertext side
 * is a property to preserve, so it is an invariant and a test rather than a
 * comment.
 */

import { guardDecode, parsePayload } from '@platform-sec/sensitive-string-secrets';
import type { ResolvedSecretRef } from '@platform-sec/sensitive-string-secrets';
import { compileClassification } from '@platform-sec/sensitive-string-core';
import type { ClassificationSpec, FieldClass } from '@platform-sec/sensitive-string-core';

/** The marker SOPS leaves in place of an encrypted scalar. */
export const ENC_MARKER = /^ENC\[[A-Za-z0-9_]+,/;

/** The metadata block SOPS adds at the document root. It is not payload. */
export const SOPS_BLOCK = 'sops';

export type SopsFormat = 'yaml' | 'json' | 'env' | 'ini';

/** The format a path implies, which SOPS itself also decides by extension. */
export function formatFor(path: string): SopsFormat {
  const lower = path.toLowerCase();

  if (lower.endsWith('.json')) {
    return 'json';
  }

  if (lower.endsWith('.env') || lower.includes('.env.')) {
    return 'env';
  }

  if (lower.endsWith('.ini')) {
    return 'ini';
  }

  return 'yaml';
}

/** A YAML parser, supplied by the caller because it is an optional peer. */
export type YamlParser = (source: string) => unknown;

/**
 * Parse the encrypted document.
 *
 * Every parser here runs on ciphertext. `guardDecode` still wraps them, because
 * a parse failure's message is the parser's own and naming the file rather than
 * its contents is the house rule whichever side of the boundary it is on.
 */
export function parseCiphertext(
  source: string,
  format: SopsFormat,
  ref: ResolvedSecretRef,
  yaml: YamlParser | undefined
): Record<string, unknown> {
  if (format === 'json') {
    return parsePayload(source, ref);
  }

  if (format === 'env' || format === 'ini') {
    return parseEnv(source);
  }

  if (yaml === undefined) {
    throw new TypeError(
      `Deriving classification from a YAML document needs a YAML parser. Install the 'yaml' ` +
        `peer dependency, or pass { yamlParse } to the source, or supply an explicit ` +
        `classification so nothing has to read the encrypted file.`
    );
  }

  const parsed = guardDecode(() => yaml(source), ref, 'YAML');

  return parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)
    ? {}
    : (parsed as Record<string, unknown>);
}

/**
 * A dotenv or ini document, flat.
 *
 * Section headers are dropped rather than becoming a prefix, because SOPS's own
 * ini handling is flat in the same way and a derived key that does not match
 * the decrypted document's key would classify nothing.
 */
function parseEnv(source: string): Record<string, unknown> {
  const parsed: Record<string, unknown> = {};

  for (const line of source.split('\n')) {
    const trimmed = line.trim();

    if (trimmed === '' || trimmed.startsWith('#') || trimmed.startsWith('[')) {
      continue;
    }

    const at = trimmed.indexOf('=');

    if (at === -1) {
      continue;
    }

    parsed[trimmed.slice(0, at).trim()] = trimmed.slice(at + 1).trim();
  }

  return parsed;
}

/**
 * Every leaf's dot path, and whether SOPS encrypted it.
 *
 * Arrays are walked by index, because SOPS encrypts array elements
 * individually and an array of secrets is a real shape. The `sops` block at the
 * document root is skipped: it is the tool's own metadata, its values are not
 * payload, and it holds the recipient list.
 */
export function encryptedPaths(document: Readonly<Record<string, unknown>>): Map<string, boolean> {
  const found = new Map<string, boolean>();

  function walk(value: unknown, prefix: string): void {
    if (value !== null && typeof value === 'object') {
      const entries = Array.isArray(value)
        ? value.map((entry, index) => [String(index), entry] as const)
        : Object.entries(value as Record<string, unknown>);

      for (const [key, entry] of entries) {
        walk(entry, prefix === '' ? key : `${prefix}.${key}`);
      }

      return;
    }

    found.set(prefix, typeof value === 'string' && ENC_MARKER.test(value));
  }

  for (const [key, value] of Object.entries(document)) {
    if (key === SOPS_BLOCK) {
      continue;
    }

    walk(value, key);
  }

  return found;
}

export interface DeriveOptions {
  /** The class an encrypted leaf gets. Defaults to `credential`. */
  readonly encryptedAs?: FieldClass;
  /**
   * Promote or demote derived classes.
   *
   * A rule that would demote a derived `credential` needs
   * `allowDemotion: true`, because a spec quietly loosening what SOPS
   * encrypted is the drift this derivation exists to prevent.
   */
  readonly rules?: ClassificationSpec['rules'];
  readonly allowDemotion?: boolean;
}

const ORDER: Readonly<Record<FieldClass, number>> = { plain: 0, sensitive: 1, credential: 2 };

/**
 * The spec for a decrypted document, derived from its encrypted form.
 *
 * `fallback` is `credential` rather than `plain`. Every key the encrypted file
 * carried is in `fields`, so the fallback only ever applies to a key that
 * appeared in the decrypted output and not in the ciphertext, which should not
 * happen and is not a case to be relaxed about.
 */
export function deriveSpec(
  document: Readonly<Record<string, unknown>>,
  options: DeriveOptions = {}
): ClassificationSpec {
  const encryptedAs = options.encryptedAs ?? 'credential';
  const fields: Record<string, FieldClass> = {};
  // Through core's compiler, which strips `g` and `y`. A caller's pattern is
  // reused across every key of the document, and a stateful one answers `true`
  // then `false` for the same key.
  const compiled = compileClassification(
    options.rules === undefined ? {} : { rules: options.rules }
  );

  for (const [path, encrypted] of encryptedPaths(document)) {
    const derived: FieldClass = encrypted ? encryptedAs : 'plain';
    const override = compiled.classify(path, [path.slice(path.lastIndexOf('.') + 1)]);

    if (override === undefined) {
      fields[path] = derived;
      continue;
    }

    const loosens = (ORDER[override] ?? 0) < (ORDER[derived] ?? 0);

    if (loosens && options.allowDemotion !== true) {
      throw new Error(
        `The rule for '${path}' would classify a value SOPS encrypted as '${override}', ` +
          `which is looser than the derived '${derived}'. Pass allowDemotion: true to mean it.`
      );
    }

    fields[path] = override;
  }

  return { fields, fallback: 'credential' };
}
