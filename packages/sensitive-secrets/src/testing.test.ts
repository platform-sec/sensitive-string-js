import { describe, it, expect } from 'vitest';

import { BaseSecretSource } from './source.js';
import {
  CanaryLeakError,
  allStrings,
  assertNoCanary,
  assertNoCanaryInError,
  errorText,
  recorder,
  safeJson,
  sourceClassesIn,
  sweep,
} from './testing.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

describe('errorText', () => {
  it('renders a message, a stack, and a cause chain', () => {
    const text = errorText(new Error('outer', { cause: new Error(`inner ${CANARY}`) }));

    expect(text).toContain('outer');
    expect(text).toContain(CANARY);
  });

  it('renders a thrown non-error', () => {
    expect(errorText({ note: CANARY })).toContain(CANARY);
  });

  it('stops on a cause cycle rather than looping', () => {
    const cyclic = new Error('outer') as Error & { cause?: unknown };
    cyclic.cause = cyclic;

    expect(errorText(cyclic)).toContain('outer');
  });

  it('reaches a cause several links down', () => {
    const deep = new Error('a', {
      cause: new Error('b', { cause: new Error('c', { cause: new Error(CANARY) }) }),
    });

    expect(errorText(deep)).toContain(CANARY);
  });
});

describe('safeJson', () => {
  it('renders an ordinary value', () => {
    expect(safeJson({ a: 1 })).toBe('{"a":1}');
  });

  it('survives a cycle', () => {
    const cyclic: Record<string, unknown> = { a: 1 };
    cyclic['self'] = cyclic;

    expect(safeJson(cyclic)).toContain('[Circular]');
  });

  it('survives a BigInt, which JSON.stringify throws on', () => {
    expect(safeJson({ big: 10n })).toContain('10');
  });

  it('survives a throwing getter', () => {
    const hostile = {
      get boom(): string {
        throw new Error('nope');
      },
    };

    expect(() => safeJson(hostile)).not.toThrow();
  });

  it('renders an undefined value rather than returning undefined', () => {
    expect(safeJson(undefined)).toBe('undefined');
  });

  it('unpacks an error, which JSON.stringify otherwise renders as an empty object', () => {
    expect(safeJson(new Error(CANARY))).toContain(CANARY);
  });
});

describe('allStrings', () => {
  it('reaches into a Map, a Set, an array, and an object', () => {
    const found = allStrings({
      map: new Map([['k', CANARY]]),
      set: new Set([CANARY]),
      list: [CANARY],
      nested: { deep: CANARY },
    });

    expect(found.filter((entry) => entry === CANARY)).toHaveLength(4);
  });

  it('includes key names, since a key can carry a value too', () => {
    expect(allStrings({ [CANARY]: 'ordinary' })).toContain(CANARY);
  });

  it('renders numbers and booleans', () => {
    expect(allStrings({ n: 5, b: true })).toContain('5');
  });

  it('stops at a depth limit rather than recursing forever', () => {
    const cyclic: Record<string, unknown> = {};
    cyclic['self'] = cyclic;

    expect(() => allStrings(cyclic)).not.toThrow();
  });

  it('ignores a function, which has no value to leak', () => {
    expect(allStrings(() => CANARY)).toEqual([]);
  });
});

describe('assertNoCanary', () => {
  it('passes for a value that does not hold the canary', () => {
    expect(() => assertNoCanary(CANARY, { a: 'ordinary' }, 'a value')).not.toThrow();
  });

  it('names where the leak was found', () => {
    expect(() => assertNoCanary(CANARY, { a: CANARY }, 'a value')).toThrow(
      /Canary leaked in a value/
    );
  });
});

describe('assertNoCanaryInError', () => {
  it('catches a canary in a cause chain', () => {
    const chained = new Error('outer', { cause: new Error(CANARY) });

    expect(() => assertNoCanaryInError(CANARY, chained, 'a call')).toThrow(CanaryLeakError);
  });

  it('passes for an error that names the source rather than the content', () => {
    expect(() =>
      assertNoCanaryInError(CANARY, new Error("Secret 'prod/db' is not valid JSON."), 'a call')
    ).not.toThrow();
  });
});

describe('sweep', () => {
  it('reports which cases threw', async () => {
    const results = await sweep(CANARY, [
      { name: 'resolves', run: () => 'ordinary' },
      {
        name: 'throws',
        run: () => {
          throw new Error('no content here');
        },
      },
    ]);

    expect(results).toEqual([
      { name: 'resolves', threw: false },
      { name: 'throws', threw: true },
    ]);
  });

  it('fails when a case resolves with the canary', async () => {
    await expect(sweep(CANARY, [{ name: 'leaks', run: () => ({ v: CANARY }) }])).rejects.toThrow(
      CanaryLeakError
    );
  });

  it('fails when a case throws with the canary, rather than counting it as a pass', async () => {
    await expect(
      sweep(CANARY, [
        {
          name: 'leaks',
          run: () => {
            throw new Error(`bad token ${CANARY}`);
          },
        },
      ])
    ).rejects.toThrow(CanaryLeakError);
  });

  it('does not swallow its own leak error as a case failure', async () => {
    // The leak is raised from inside the try, so without the rethrow the catch
    // would run the error sweep over it and report a pass.
    await expect(sweep(CANARY, [{ name: 'leaks', run: () => CANARY }])).rejects.toBeInstanceOf(
      CanaryLeakError
    );
  });
});

describe('sourceClassesIn', () => {
  class Fake extends BaseSecretSource {
    protected readonly sourceName = 'fake';
    protected fetchSecret(): Promise<null> {
      return Promise.resolve(null);
    }
  }

  it('finds a source subclass', () => {
    expect(sourceClassesIn({ Fake })).toEqual(['Fake']);
  });

  it('ignores the base class itself, which is abstract', () => {
    expect(sourceClassesIn({ BaseSecretSource })).toEqual([]);
  });

  it('ignores everything that is not a source', () => {
    expect(sourceClassesIn({ helper: () => undefined, value: 1, Klass: Error })).toEqual([]);
  });
});

describe('recorder', () => {
  it('records what it was handed and never sends it', () => {
    const calls = recorder<string>();

    calls.record('one');
    calls.record('two');

    expect(calls.calls).toEqual(['one', 'two']);
  });

  it('resets', () => {
    const calls = recorder<string>();

    calls.record('one');
    calls.reset();

    expect(calls.calls).toEqual([]);
  });
});
