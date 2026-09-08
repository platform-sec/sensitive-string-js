import { SensitiveStringError } from './errors.js';

/**
 * Raised when a `SensitiveString` reaches BSON serialisation unrevealed.
 *
 * BSON honours `toBSON()` on a value and ignores `toJSON()` (measured against
 * `bson` 7.3.2). Without a `toBSON`, an instance handed to any MongoDB write is
 * serialised by its own enumerable properties, which are `klass` and `label`:
 * the document stores `{ klass: 'credential', label: 'token' }` and the value is
 * gone. Nothing throws, nothing logs, and the column looks populated.
 *
 * That is worse than a leak in one specific way, which is why this throws where
 * {@link SensitiveString.toJSON} redacts. A leak is loud once someone reads the
 * log; this is silent until an authentication fails in production, and by then
 * the original value is not recoverable from the document. It is also an
 * authentication bypass on the read side: every classified value serialises to
 * the same husk, so a filter built from one matches a document written from
 * another.
 *
 * `toJSON` must not throw because logging must not throw, and a redacted log
 * line is still useful. `toBSON` is only ever called when a value is about to be
 * persisted or matched, and neither has a useful degraded outcome.
 */
export class SensitiveBsonError extends SensitiveStringError {
  override readonly name = 'SensitiveBsonError';
  override readonly code = 'bson-serialization-refused';

  constructor(klass: string, label: string | undefined) {
    super(
      `A SensitiveString<${label ? `${klass}:${label}` : klass}> reached BSON serialization ` +
        'without being revealed. Storing it would persist { klass, label } and lose the value, ' +
        'and matching on it would match every other value of the same class. Reveal it at the ' +
        'write boundary, or use @platform-sec/sensitive-string-mongoose.'
    );
  }
}
