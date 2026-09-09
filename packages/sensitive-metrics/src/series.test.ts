import { describe, expect, it, vi } from 'vitest';
import { BoundedCounter } from './series.js';
import { OVERFLOW_LABEL } from './types.js';

const FOLDABLE = new Set(['label']);

function counter(overrides: Partial<ConstructorParameters<typeof BoundedCounter>[0]> = {}) {
  return new BoundedCounter({
    name: 'test_total',
    help: 'test',
    dimensions: ['class', 'label'],
    foldable: FOLDABLE,
    maxSeries: 3,
    mode: 'aggregate',
    ...overrides,
  });
}

describe('BoundedCounter', () => {
  it('accumulates into one series per distinct label tuple', () => {
    const c = counter();

    c.inc(['credential', 'api_key']);
    c.inc(['credential', 'api_key']);
    c.inc(['sensitive', 'email']);

    expect(c.size).toBe(2);
    expect(c.total()).toBe(3);
    expect(c.breakdown('label')).toEqual({ api_key: 2, email: 1 });
  });

  it('cannot be made to collide two different label tuples on one series', () => {
    // A separator-joined key would put these two in the same series: with a
    // comma, 'a,b' and ['a', 'b'] render identically, which lets a
    // caller-chosen label forge another tuple's identity. The trie cannot
    // express the collision at all, because each level keys on one whole value
    // and nothing is ever concatenated.
    const c = counter({ maxSeries: 10 });

    c.inc(['a,b', '']);
    c.inc(['a', 'b']);

    expect(c.size).toBe(2);
  });

  describe('the cardinality cap (INV-MET-002)', () => {
    it('folds caller-supplied dimensions once the cap is reached, keeping the total', () => {
      const c = counter({ maxSeries: 3 });

      for (let index = 0; index < 50; index++) {
        c.inc(['credential', `label_${String(index)}`]);
      }

      expect(c.total()).toBe(50);
      // Three admitted normally, plus one overflow series for the one
      // non-folding combination present.
      expect(c.size).toBe(4);
      expect(c.breakdown('label')[OVERFLOW_LABEL]).toBe(47);
    });

    it('keeps the dimensions the library bounds, so the overflow is still readable', () => {
      const c = counter({ maxSeries: 2 });

      for (let index = 0; index < 20; index++) {
        c.inc(['credential', `a${String(index)}`]);
        c.inc(['sensitive', `b${String(index)}`]);
      }

      expect(c.breakdown('class')).toEqual({ credential: 20, sensitive: 20 });
    });

    it("drops rather than counts under mode 'drop'", () => {
      const c = counter({ maxSeries: 2, mode: 'drop' });

      expect(c.inc(['credential', 'a'])).toBe('recorded');
      expect(c.inc(['credential', 'b'])).toBe('recorded');
      expect(c.inc(['credential', 'c'])).toBe('dropped');

      expect(c.total()).toBe(2);
      expect(c.size).toBe(2);
    });

    it("warns once and then folds silently under mode 'warn'", () => {
      const warn = vi.spyOn(process, 'emitWarning').mockImplementation(() => undefined);

      try {
        const c = counter({ maxSeries: 1, mode: 'warn' });

        c.inc(['credential', 'a']);
        c.inc(['credential', 'b']);
        c.inc(['credential', 'c']);

        expect(warn).toHaveBeenCalledTimes(1);
        expect(String(warn.mock.calls[0]?.[0])).toContain('test_total');
      } finally {
        warn.mockRestore();
      }
    });

    it('drops an event with nothing left to fold rather than admitting it past the cap', () => {
      const c = counter({ dimensions: ['class'], foldable: FOLDABLE, maxSeries: 1 });

      expect(c.inc(['credential'])).toBe('recorded');
      expect(c.inc(['sensitive'])).toBe('dropped');
      expect(c.size).toBe(1);
    });

    it('holds a hard ceiling even where the non-folding dimensions are unbounded', () => {
      // `class` never folds, so a caller feeding arbitrary values into it,
      // which recordRefusal makes possible through an error subclass of its
      // own, would grow the counter without the ceiling.
      const c = counter({ maxSeries: 4 });

      for (let index = 0; index < 500; index++) {
        c.inc([`class_${String(index)}`, 'x']);
      }

      expect(c.size).toBeLessThanOrEqual(8);
    });
  });

  it('reports totals filtered on any subset of its dimensions', () => {
    const c = counter({ maxSeries: 10 });

    c.inc(['credential', 'api_key'], 3);
    c.inc(['sensitive', 'api_key'], 5);

    expect(c.total({ label: 'api_key' })).toBe(8);
    expect(c.total({ class: 'credential' })).toBe(3);
    expect(c.total({ class: 'credential', label: 'nope' })).toBe(0);
    // An undefined field is not a filter, so this is the unfiltered total.
    expect(c.total({ class: undefined })).toBe(8);
  });

  it('returns no rows for a dimension it does not carry', () => {
    expect(counter().breakdown('surface')).toEqual({});
  });

  it('orders series by label value, not by an internal key that sorts on length', () => {
    // A length-prefixed key sorts 'zz' before 'aaa'. Nothing depends on the
    // order beyond its being stable, but a scrape is read by people, and the
    // doc comment claims value order.
    const c = counter({ maxSeries: 10 });

    c.inc(['credential', 'zz']);
    c.inc(['credential', 'aaa']);

    expect(c.collect().map((series) => series.labels['label'])).toEqual(['aaa', 'zz']);
  });

  it('emits series in a stable order regardless of insertion order', () => {
    const first = counter({ maxSeries: 10 });
    const second = counter({ maxSeries: 10 });

    first.inc(['sensitive', 'z']);
    first.inc(['credential', 'a']);
    second.inc(['credential', 'a']);
    second.inc(['sensitive', 'z']);

    expect(first.collect()).toEqual(second.collect());
  });
});
