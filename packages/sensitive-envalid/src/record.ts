import { SensitiveString } from '@platform-sec/sensitive-string-core';
import type { SensitivityClass } from '@platform-sec/sensitive-string-core';
import { probeKeys, probeProperty } from '@platform-sec/sensitive-string-env';
import type { EnvRecord } from '@platform-sec/sensitive-string-env';

/**
 * Convert an envalid result into the plain `EnvRecord` of the shared package.
 *
 * The object envalid returns is a Proxy that throws a `ReferenceError` for any
 * property that was not declared. `core`'s redaction walks now treat a refusal
 * as absence, so logging one is safe; what the fix does not do is make every
 * strict proxy safe everywhere, because a third-party serializer that probes an
 * unknown property on the same object is outside this library.
 *
 * Two reasons to convert, both of which survive that fix. `toChildEnv` takes an
 * `EnvRecord`. And the proxy still throws for the application's own mistakes: a
 * typo in `env.DB_PASSWROD` is a `ReferenceError` at the read rather than
 * `undefined`, which is a feature of envalid and a hazard for any code that
 * probes optionally.
 *
 * `removed` is empty and `kernelCopy` is `'unknown'`: this record came from
 * envalid, which deletes nothing from `process.env` and cannot say what the
 * kernel holds. Use `loadEnv` for those.
 */
export function toEnvRecord(env: object): EnvRecord {
  const fields = new Map<string, SensitiveString<SensitivityClass>>();
  const plain = new Map<string, string>();
  const names: string[] = [];

  for (const name of probeKeys(env)) {
    names.push(name);

    const value = probeProperty(env, name);

    if (value instanceof SensitiveString) {
      // `instanceof` narrows to `SensitiveString<any>`, because the class is a
      // type parameter the check cannot see. The runtime class is one of the
      // two, and reading `.klass` off it would prove nothing the assertion does
      // not already say.
      fields.set(name, value as SensitiveString<SensitivityClass>);
      continue;
    }

    // envalid parses, so the plain half holds numbers, booleans and whatever a
    // `json()` validator produced. An `EnvRecord`'s plain half is strings,
    // because its job is to feed a child environment and a log line, so a
    // primitive is rendered and anything structural is left out of both maps
    // rather than stringified into something a child could not use.
    if (typeof value === 'string') {
      plain.set(name, value);
    } else if (typeof value === 'number' || typeof value === 'boolean') {
      plain.set(name, String(value));
    }
  }

  return { fields, plain, names, removed: [], kernelCopy: 'unknown' };
}
