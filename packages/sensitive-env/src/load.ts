import { compileEnvSpec, emptyCounts } from './classify.js';
import { readEnvFile } from './parse.js';
import { kernelCopyNames, removeFromProcessEnv } from './remove.js';
import { probeKeys, probeProperty } from './probe.js';
import { wrapFlatCompiled } from './wrap.js';
import type {
  DroppedLine,
  EnvExplanation,
  EnvLoadEvent,
  EnvRecord,
  EnvSpec,
  FieldClass,
  LoadEnvOptions,
} from './types.js';

/** The merged source, and everything the merge learned on the way. */
interface MergedSource {
  readonly values: Record<string, string | undefined>;
  readonly files: string[];
  readonly droppedLines: DroppedLine[];
  readonly unexpectedNames: number;
}

/**
 * Read every configured file, then the source, with later winning.
 *
 * Files lose to each other in order and all of them lose to `source`, which is
 * the precedence every loader in this row uses: a `.env` file is a default and
 * the real environment is the override.
 *
 * A key the source carries with a non-string value does not erase a string a
 * file supplied. `process.env` has no such key once a variable is deleted, so
 * this only comes up for a caller-supplied source, where treating `undefined`
 * as an override would mean an explicitly absent key silently removing a
 * configured default.
 */
function mergeSources(options: LoadEnvOptions): MergedSource {
  const values: Record<string, string | undefined> = Object.create(null) as Record<
    string,
    string | undefined
  >;
  const files: string[] = [];
  const droppedLines: DroppedLine[] = [];
  let unexpectedNames = 0;

  for (const file of options.files ?? []) {
    const parsed = readEnvFile(file);

    if (parsed === undefined) {
      continue;
    }

    files.push(file);
    droppedLines.push(...parsed.droppedLines);
    unexpectedNames += parsed.unexpectedNames;

    for (const name of Object.keys(parsed.values)) {
      values[name] = parsed.values[name];
    }
  }

  const source = options.source ?? process.env;

  for (const name of probeKeys(source)) {
    const value = probeProperty(source, name);

    if (typeof value === 'string') {
      values[name] = value;
    } else if (!Object.hasOwn(values, name)) {
      values[name] = undefined;
    }
  }

  return { values, files, droppedLines, unexpectedNames };
}

/**
 * Read the environment, classify every name, and wrap what the spec classified.
 *
 * Synchronous, because every source it reads is synchronous and configuration
 * loading happens before the event loop matters.
 *
 * The source is walked once and the spec's rules are compiled once per call,
 * not once per name.
 *
 * @example
 * ```ts
 * const record = loadEnv(
 *   { fields: { DB_PASSWORD: 'credential' }, rules: commonSecretNameRules, fallback: 'plain' },
 *   { files: ['.env'], removeFromProcessEnv: true, checkKernelCopy: true }
 * );
 *
 * record.fields.get('DB_PASSWORD'); // SensitiveString<credential:DB_PASSWORD>
 * record.plain.get('PORT');         // '3000'
 * record.removed;                   // ['DB_PASSWORD']
 * record.kernelCopy;                // ['DB_PASSWORD'] <- exported before exec
 * ```
 *
 * Pure with respect to `process.env` unless `removeFromProcessEnv` is set. It
 * never writes to `process.env`, under any option: a "re-export for
 * compatibility" switch would be a supported path for putting a raw secret back
 * after removing it, and `toChildEnv` already covers the legitimate need.
 */
export function loadEnv(spec: EnvSpec, options: LoadEnvOptions = {}): EnvRecord {
  const compiled = compileEnvSpec(spec);
  const merged = mergeSources(options);
  const wrapped = wrapFlatCompiled(merged.values, spec, compiled);

  const removed =
    options.removeFromProcessEnv === true ? removeFromProcessEnv([...wrapped.fields.keys()]) : [];

  const kernelCopy =
    options.checkKernelCopy === true ? kernelCopyNames([...wrapped.fields.keys()]) : [];

  const record: EnvRecord = {
    fields: wrapped.fields,
    plain: wrapped.plain,
    names: wrapped.names,
    removed,
    kernelCopy,
  };

  if (options.onLoad !== undefined) {
    const event: EnvLoadEvent = {
      names: record.names,
      classes: wrapped.classes,
      counts: wrapped.counts,
      files: merged.files,
      droppedLines: merged.droppedLines,
      removed,
      kernelCopy,
      unexpectedNames: merged.unexpectedNames,
    };
    options.onLoad(event);
  }

  return record;
}

/**
 * Report the classification each name would receive, wrapping nothing.
 *
 * This is how a specification is reviewed against a real environment and
 * checked into a test, so that adoption can be one variable at a time. It reads
 * no value into the result and wraps nothing, so it is safe to log in full and
 * safe to run before anything has been decided.
 *
 * @example
 * ```ts
 * it('classifies every secret in the deployed environment', () => {
 *   const explained = explainEnv(spec, { source: deployedNames });
 *   expect(explained.classes.get('DB_PASSWORD')).toBe('credential');
 *   expect(explained.counts.credential).toBe(3);
 * });
 * ```
 */
export function explainEnv(spec: EnvSpec, options: LoadEnvOptions = {}): EnvExplanation {
  const compiled = compileEnvSpec(spec);
  const merged = mergeSources(options);

  const classes = new Map<string, FieldClass>();
  const counts = emptyCounts();
  const names: string[] = [];

  for (const name of Object.keys(merged.values)) {
    const klass = compiled.classify(name) ?? spec.fallback;
    names.push(name);
    classes.set(name, klass);
    counts[klass]++;
  }

  return {
    names,
    classes,
    counts,
    droppedLines: merged.droppedLines,
    unexpectedNames: merged.unexpectedNames,
  };
}
