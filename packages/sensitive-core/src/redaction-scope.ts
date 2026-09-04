import { getGlobalSingleton } from './global-state.js';
import type { SensitivityClass } from './types.js';

/**
 * The mark a redaction walk holds while it runs caller code.
 *
 * `redactInStructure` calls an object's own `toJSON()` to learn its JSON form,
 * and a `toJSON()` is free to call `reveal()`. The walk cannot tell a plain
 * string that was always plain from one that was a `SensitiveString` a moment
 * ago, so a `toJSON()` that reveals would put the raw value into the log line
 * the walk exists to keep it out of, and the reveal would be audited as if the
 * application had asked for it. Skipping user `toJSON()` methods is the wrong
 * fix: a `toJSON()` that omits a raw field hides it, and walking own
 * properties instead would expose that field.
 *
 * So the walk sets the mark, and the raw-value gate refuses to disclose a
 * value while it is set. The refusal is a throw inside the caller's
 * `toJSON()`, which the walk already absorbs by falling back to own
 * properties, where the instance is still an instance and is redacted as one.
 * Comparison is not disclosure and stays allowed; so does redaction, which
 * the walk itself performs.
 *
 * The depth lives in process-global state so that a walk in one physical copy
 * of core is seen by the gate in another. A walk is synchronous, so a plain
 * counter is the right shape: nothing can interleave with it.
 */
interface RedactionScope {
  depth: number;
}

const scope = getGlobalSingleton<RedactionScope>('redaction-scope', () => ({ depth: 0 }));

/** Run caller code on the walk's behalf, with the mark set for its duration. */
export function runInsideRedaction<T>(operation: () => T): T {
  scope.depth += 1;

  try {
    return operation();
  } finally {
    scope.depth -= 1;
  }
}

/** Whether a redaction walk is running caller code right now. */
export function isInsideRedaction(): boolean {
  return scope.depth > 0;
}

/**
 * Raised when `reveal()`, `mask()`, `serialize()` or a transform is called from
 * inside a `toJSON()` that a redaction walk is running.
 *
 * A caller sees this only by catching it inside that `toJSON()`: the walk
 * itself absorbs the throw and redacts the object's own properties instead.
 */
export class RevealDuringRedactionError extends Error {
  override readonly name = 'RevealDuringRedactionError';

  constructor(
    readonly klass: SensitivityClass,
    readonly label?: string
  ) {
    super(
      `Cannot reveal a ${klass} value${label !== undefined ? ` '${label}'` : ''} from inside a ` +
        'redaction walk: a toJSON() that reveals would put the raw value into a log line. ' +
        'Return the SensitiveString itself and let the walk redact it.'
    );
  }
}
