/**
 * Operations performed against objects the library did not create.
 *
 * A redaction walk has to ask an arbitrary object a series of questions: is
 * this a `serialize()` result, is this a stream, what is your tag, what is your
 * prototype, do you have a `toJSON`, what are your own properties. None of
 * those is universally safe. Every one of them runs through a hook the object
 * controls, and an object is free to throw from any of them:
 *
 * | The walk does | The object controls it through |
 * |---|---|
 * | `obj.name` | a `get` trap, or a getter anywhere on the prototype chain |
 * | `Object.prototype.toString.call(obj)` | a `Symbol.toStringTag` getter, reached the same way |
 * | `Object.getPrototypeOf(obj)` | a `getPrototypeOf` trap |
 * | `'toJSON' in obj` | a `has` trap |
 * | `obj.toJSON()` | the method body |
 * | `Object.keys(obj)` / `Object.entries(obj)` | `ownKeys`, `getOwnPropertyDescriptor`, and every enumerable getter |
 * | `String(obj)` | a `toString` or `Symbol.toPrimitive` |
 * | `for (const entry of map)`, `array.map()`, `date.getTime()` | a Proxy in front of the built-in, whose target alone has the internal slot, or a subclass iterator |
 * | `error.message` | a getter on the instance |
 *
 * The one that matters most in practice is not a Proxy at all. An ordinary
 * object with an enumerable getter that throws is what an ORM produces for a
 * relation that was not loaded, and `Object.entries` invokes every one of them.
 * The Proxy cases are real too: envalid's `cleanEnv` result throws a
 * `ReferenceError` for any variable that was not declared, which is what first
 * exposed this class of defect.
 *
 * The rule these functions encode is that **failing to read is not a reason to
 * fail the redaction**. A logger calling `safeLog` must not be the thing that
 * takes down the request, and an object that refuses to answer must not be able
 * to turn a redaction into an exception. Each function below answers with the
 * safe interpretation of a refusal, and each caller documents what it does with
 * that answer.
 */

/** What a walk substitutes for an object it could not read at all. */
export const UNREADABLE = '[Unreadable]';

/**
 * Read a named property, treating a refusal as absence.
 *
 * Reporting absence is the safe answer for every caller of *this* function. It
 * never decides whether a value is redacted: it answers duck-type questions
 * that decide whether a walk replaces an object wholesale or descends into it,
 * and descending still redacts every `SensitiveString` inside. So an object
 * that refuses to answer one property is walked like any other rather than
 * failing the whole redaction.
 *
 * `probeEntries` is the one below that does decide, and it says so.
 */
export function probeProperty(value: object, name: string): unknown {
  try {
    return (value as Record<string, unknown>)[name];
  } catch {
    return undefined;
  }
}

/**
 * The object's `Object.prototype.toString` tag.
 *
 * A refusal answers `'[object Object]'`, which routes the caller into the
 * ordinary-object branch and therefore into descending and redacting. The other
 * branch is `String(obj)`, which would ask the same uncooperative object
 * another question and hide anything it holds behind one string.
 */
export function probeTag(value: object): string {
  try {
    return Object.prototype.toString.call(value);
  } catch {
    return '[object Object]';
  }
}

/**
 * The object's prototype, or `undefined` when it refuses to say.
 *
 * `undefined` is distinct from `null`: a null-prototype object answers `null`
 * and is walked as a plain object, whereas one that refuses is not claimed to
 * be anything. The callers treat the refusal as "not `Object.prototype`", which
 * sends it to the tag check, which sends it on to be walked.
 */
export function probePrototype(value: object): object | null | undefined {
  try {
    return Object.getPrototypeOf(value) as object | null;
  } catch {
    return undefined;
  }
}

/**
 * Whether the object offers a callable method under this name.
 *
 * Covers both hooks in one place: `in` goes through a `has` trap and the read
 * goes through a `get` trap. A refusal from either answers `false`, so the
 * caller walks own properties instead of trusting a method it cannot reach.
 */
export function probeMethod(value: object, name: string): (() => unknown) | undefined {
  try {
    if (!(name in value)) {
      return undefined;
    }
  } catch {
    return undefined;
  }

  const method = probeProperty(value, name);

  return typeof method === 'function' ? (method as () => unknown) : undefined;
}

/** What a guarded call returned, and whether it returned at all. */
export interface ProbeResult {
  readonly ok: boolean;
  readonly value: unknown;
}

/**
 * Call a method the object supplied, treating a throw as no answer.
 *
 * `toJSON` is caller code and is entitled to throw. What it is not entitled to
 * do is turn a log line into an exception, so a throw here means the walk falls
 * back to the object's own properties, which is the same path an object with no
 * `toJSON` takes.
 */
export function probeCall(method: () => unknown, thisArg: object): ProbeResult {
  try {
    return { ok: true, value: method.call(thisArg) };
  } catch {
    return { ok: false, value: undefined };
  }
}

/**
 * Run one operation a built-in performs on the object, treating a throw as no
 * answer.
 *
 * Iterating a Map or a Set, mapping an array, reading a Date's time: each is
 * the object's own code once a Proxy stands in front of it. `Map.prototype.entries`
 * refuses a proxy as its receiver, an array proxy may refuse `length` or an
 * index, and a Date proxy throws from every method, the `toJSON()` a serializer
 * calls later included. A partial result would claim to be the whole, so the
 * caller gets none, and substitutes {@link UNREADABLE} or its own safe answer.
 */
export function probeBuiltin<T>(operation: () => T): T | undefined {
  try {
    return operation();
  } catch {
    return undefined;
  }
}

/**
 * The object's own enumerable properties, or `undefined` when it cannot be
 * enumerated at all.
 *
 * Two failures are separated here, because they deserve different answers.
 *
 * A refusal to list the keys is total: `ownKeys` or `getOwnPropertyDescriptor`
 * threw, and nothing can be said about the object's contents. That answers
 * `undefined`, and each caller decides what an unreadable object becomes.
 *
 * A refusal to read *one* property is not: the other keys are still readable,
 * and the property that threw reads as `undefined`. That is why the values are
 * read one at a time through `probeProperty` rather than taken from
 * `Object.entries`, which invokes every enumerable getter and propagates the
 * first throw. A getter that throws is the common case, not the exotic one.
 */
export function probeEntries(value: object): [string, unknown][] | undefined {
  let keys: string[];

  try {
    keys = Object.keys(value);
  } catch {
    return undefined;
  }

  return keys.map((key) => [key, probeProperty(value, key)]);
}

/**
 * Whether the object will answer any question at all.
 *
 * `instanceof` walks the prototype chain, so an object with a `getPrototypeOf`
 * trap that throws makes every `instanceof` in a walk throw, before any of the
 * guards below get a chance to run. There are around thirty such checks across
 * the two walks, and guarding each one would be thirty places to get wrong;
 * asking once, at the top, is the same protection in one place.
 *
 * An object that will not name its prototype is unwalkable by construction, so
 * each walk substitutes its own unreadable answer and stops.
 */
export function isUnreadable(value: object): boolean {
  return probePrototype(value) === undefined;
}

/**
 * The object's string form, or `undefined` when `toString` refuses.
 *
 * Only reached for exotic objects, where the string form is the whole of what
 * the walk keeps. A refusal leaves the caller with nothing to keep, so it
 * substitutes {@link UNREADABLE}.
 */
export function probeString(value: object): string | undefined {
  try {
    // eslint-disable-next-line @typescript-eslint/no-base-to-string -- the caller has already established this object is exotic and carries its own toString
    return String(value);
  } catch {
    return undefined;
  }
}
