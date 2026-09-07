import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { describe, expect, it } from 'vitest';
import { findUnsafeParameter, parameterEntries, redactParameters } from './parameters.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';
const CENSOR = '[REDACTED:parameter]';

const instance = (): SensitiveString<'credential'> => new SensitiveString(CANARY, 'credential');
const marker = (): string => String(instance());

describe('findUnsafeParameter', () => {
  it('passes an ordinary bag through', () => {
    expect(findUnsafeParameter([1, 'plain', null, undefined, new Date()])).toBeUndefined();
    expect(findUnsafeParameter({ id: 7, name: 'plain' })).toBeUndefined();
  });

  it('finds an instance and a marker in an array, by position', () => {
    expect(findUnsafeParameter([1, instance()])).toEqual({ path: '1', kind: 'instance' });
    expect(findUnsafeParameter([1, marker()])).toEqual({ path: '1', kind: 'marker' });
  });

  it('finds one in a named bag, by key', () => {
    // `DataSource.query(sql, { e: value })` hands the runner this object
    // unchanged, and `better-sqlite3` rejects named placeholders, so the driver
    // an application develops against is often not the one that shows the hole.
    expect(findUnsafeParameter({ id: 1, e: instance() })).toEqual({
      path: 'e',
      kind: 'instance',
    });
  });

  it('finds one in a Map', () => {
    // The shape the TypeORM copy did not walk.
    const bag = new Map<string, unknown>([
      ['id', 1],
      ['token', instance()],
    ]);
    expect(findUnsafeParameter(bag)).toEqual({ path: 'token', kind: 'instance' });
  });

  it('finds one in a bag whose prototype is not Object.prototype', () => {
    // The other shape the TypeORM copy passed over: refusing has to be
    // exhaustive, so a class instance and a bag from another realm are walked.
    class Params {
      id = 1;
      token: unknown = instance();
    }
    expect(findUnsafeParameter(new Params())).toEqual({ path: 'token', kind: 'instance' });
  });

  it('descends into a nested container, and names the path', () => {
    // The depth the Drizzle copy did not have: its walk was one level.
    expect(findUnsafeParameter([{ filters: [1, instance()] }])).toEqual({
      path: '0.filters[1]',
      kind: 'instance',
    });
  });

  it('does not descend into a value that holds nothing', () => {
    const buffer = Buffer.from(CANARY);
    expect(findUnsafeParameter([buffer, new Date(), 42n])).toBeUndefined();
  });

  it('terminates on a cycle', () => {
    const cyclic: Record<string, unknown> = { id: 1 };
    cyclic['self'] = cyclic;
    expect(findUnsafeParameter([cyclic])).toBeUndefined();

    cyclic['token'] = instance();
    expect(findUnsafeParameter([cyclic])).toEqual({ path: '0.token', kind: 'instance' });
  });

  it('names no value in what it reports', () => {
    const found = findUnsafeParameter([instance(), marker()]);
    expect(JSON.stringify(found)).not.toContain(CANARY);
  });
});

describe('parameterEntries', () => {
  it('reads the three bag shapes and skips a primitive', () => {
    expect(parameterEntries(['a', 'b'])).toEqual([
      ['0', 'a'],
      ['1', 'b'],
    ]);
    expect(parameterEntries({ e: 'a' })).toEqual([['e', 'a']]);
    expect(parameterEntries(new Map([['e', 'a']]))).toEqual([['e', 'a']]);
    expect(parameterEntries('scalar')).toEqual([]);
    expect(parameterEntries(null)).toEqual([]);
  });
});

describe('redactParameters', () => {
  it('keeps everything that is not a string when the statement is untouched', () => {
    const params = [1, true, null, new Date(0)];
    expect(redactParameters(params, false, CENSOR)).toBe(params);
  });

  it('censors every string once the statement is one to censor', () => {
    expect(redactParameters([1, 'alice@example.com'], true, CENSOR)).toEqual([1, CENSOR]);
  });

  it('censors an instance and a marker whatever the statement looked like', () => {
    expect(redactParameters([instance(), marker(), 'plain'], false, CENSOR)).toEqual([
      CENSOR,
      CENSOR,
      'plain',
    ]);
  });

  it('keeps the bag identity when nothing changed', () => {
    const params = { id: 1, when: new Date(0) };
    expect(redactParameters(params, false, CENSOR)).toBe(params);
  });

  it('rebuilds a named bag when something changed', () => {
    expect(redactParameters({ id: 1, e: instance() }, false, CENSOR)).toEqual({
      id: 1,
      e: CENSOR,
    });
  });

  it('leaves a Map alone rather than rebuilding it as a plain object', () => {
    // Deliberate asymmetry with the walk above. Refusing has to be exhaustive;
    // a log line that keeps the shape it arrived in is only a nicety, and
    // rebuilding a Map as a plain object would change what the inner logger
    // sees.
    const bag = new Map<string, unknown>([['e', instance()]]);
    expect(redactParameters(bag, true, CENSOR)).toBe(bag);
  });

  it('never emits the value', () => {
    const out = redactParameters([instance(), marker(), CANARY], true, CENSOR);
    expect(JSON.stringify(out)).not.toContain(CANARY);
  });
});
