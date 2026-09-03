import { Readable } from 'node:stream';
import { afterEach, describe, expect, it } from 'vitest';
import { SensitiveString, redactCopy, registerPolicy, resetPolicies } from './index.js';

const CANARY = 'LEAKED_SECRET_copy_9c1d';

const credential = (label?: string) => new SensitiveString(CANARY, 'credential', label);
const sensitive = (label?: string) => new SensitiveString(CANARY, 'sensitive', label);

/** Stands in for an ORM entity: a class instance with its own JSON form. */
class UserEntity {
  constructor(
    readonly id: number,
    readonly email: SensitiveString<'sensitive'>,
    readonly apiKey: SensitiveString<'credential'>
  ) {}

  toJSON(): Record<string, unknown> {
    return { id: this.id, email: this.email, apiKey: this.apiKey, kind: 'user' };
  }
}

describe('redactCopy', () => {
  afterEach(() => {
    resetPolicies();
  });

  describe('what it replaces', () => {
    it('replaces a SensitiveString at the root', () => {
      expect(redactCopy(credential())).toBe('[REDACTED:credential]');
    });

    it('replaces instances inside objects and arrays', () => {
      const copy = redactCopy({
        users: [{ email: sensitive('email') }],
        tokens: [credential(), credential()],
      });

      expect(copy).toEqual({
        users: [{ email: '[REDACTED:sensitive]' }],
        tokens: ['[REDACTED:credential]', '[REDACTED:credential]'],
      });
    });

    it('honours the class policy for instances and serialized values alike', () => {
      registerPolicy(
        {
          name: 'credential',
          redact: () => '<hidden>',
          requireConstantTimeEquals: true,
        },
        { overwrite: true }
      );

      const copy = redactCopy({ live: credential(), wire: credential().serialize() });

      expect(copy).toEqual({ live: '<hidden>', wire: '<hidden>' });
    });

    it('replaces a serialized value with the redaction of the class it names', () => {
      const copy = redactCopy({ token: credential('token').serialize() }) as { token: unknown };

      expect(copy.token).toBe('[REDACTED:credential]');
    });

    it('replaces a serialized value at the root', () => {
      expect(redactCopy(sensitive().serialize())).toBe('[REDACTED:sensitive]');
    });

    it('uses a generic marker for a serialized value of an unregistered class', () => {
      const copy = redactCopy({
        token: { __sensitive: true, klass: 'made-up', value: CANARY },
      }) as { token: unknown };

      expect(copy.token).toBe('[REDACTED]');
    });

    it('replaces anything carrying the marker, however malformed', () => {
      const copy = redactCopy({
        noClass: { __sensitive: true, value: CANARY },
        noValue: { __sensitive: true, klass: 'credential' },
        wrongType: { __sensitive: true, klass: 'credential', value: 42 },
      });

      expect(copy).toEqual({
        noClass: '[REDACTED]',
        noValue: '[REDACTED:credential]',
        wrongType: '[REDACTED:credential]',
      });
    });

    it('leaves a value produced by an explicit reveal alone', () => {
      expect(redactCopy({ email: new SensitiveString('a@b.c', 'sensitive').reveal() })).toEqual({
        email: 'a@b.c',
      });
    });
  });

  describe('what it keeps', () => {
    it.each([
      ['null', null],
      ['undefined', undefined],
      ['a string', 'plain'],
      ['a number', 42],
      ['a boolean', false],
      ['a bigint', 10n],
    ])('returns %s unchanged', (_name, value) => {
      expect(redactCopy(value)).toBe(value);
    });

    it('returns a function unchanged', () => {
      const fn = (): string => 'plain';

      expect(redactCopy(fn)).toBe(fn);
    });

    it('keeps the prototype of a class instance, so its toJSON() still runs', () => {
      const copy = redactCopy(new UserEntity(1, sensitive('email'), credential('api_key')));

      expect(copy).toBeInstanceOf(UserEntity);
      expect(JSON.parse(JSON.stringify(copy))).toEqual({
        id: 1,
        email: '[REDACTED:sensitive]',
        apiKey: '[REDACTED:credential]',
        kind: 'user',
      });
    });

    it('keeps a null prototype', () => {
      const bare = Object.create(null) as Record<string, unknown>;
      bare['secret'] = credential();

      const copy = redactCopy(bare) as Record<string, unknown>;

      expect(Object.getPrototypeOf(copy)).toBeNull();
      expect(copy['secret']).toBe('[REDACTED:credential]');
    });

    it('preserves a shared reference instead of copying it twice', () => {
      const user = { email: sensitive() };
      const copy = redactCopy({ author: user, reviewer: user }) as {
        author: unknown;
        reviewer: unknown;
      };

      expect(copy.author).toEqual({ email: '[REDACTED:sensitive]' });
      expect(copy.reviewer).toBe(copy.author);
    });

    it('keeps a cycle as a cycle', () => {
      const node: Record<string, unknown> = { secret: sensitive() };
      node['self'] = node;

      const copy = redactCopy(node) as Record<string, unknown>;

      expect(copy['secret']).toBe('[REDACTED:sensitive]');
      expect(copy['self']).toBe(copy);
      expect(() => JSON.stringify(copy)).toThrow();
    });

    it.each([
      ['a Date', new Date('2026-09-03T00:00:00.000Z')],
      ['a Map', new Map([['k', 'v']])],
      ['a Set', new Set(['v'])],
      ['a WeakMap', new WeakMap()],
      ['a RegExp', /pattern/u],
      ['a URL', new URL('https://example.com/path')],
      ['an Error', new Error('boom')],
      ['a Promise', Promise.resolve('v')],
      ['a Buffer', Buffer.from('bytes')],
      ['a Uint8Array', new Uint8Array([1, 2])],
      ['an ArrayBuffer', new ArrayBuffer(4)],
      ['a Readable', Readable.from(['bytes'])],
    ])('passes %s through by reference, at the root and as a member', (_name, member) => {
      expect(redactCopy(member)).toBe(member);
      expect((redactCopy({ member }) as { member: unknown }).member).toBe(member);
    });

    it('copies an own accessor property as its value', () => {
      const holder = {
        get secret(): SensitiveString<'credential'> {
          return credential();
        },
      };

      expect(redactCopy(holder)).toEqual({ secret: '[REDACTED:credential]' });
    });

    it('does not visit symbol keys or non-enumerable properties', () => {
      const key = Symbol('k');
      const holder: Record<string | symbol, unknown> = { [key]: credential() };
      Object.defineProperty(holder, 'hidden', { value: credential(), enumerable: false });

      const copy = redactCopy(holder) as Record<string | symbol, unknown>;

      expect(Object.getOwnPropertySymbols(copy)).toEqual([]);
      expect(Object.getOwnPropertyNames(copy)).toEqual([]);
      // Neither reaches JSON.stringify either, so nothing is lost on that path.
      expect(JSON.stringify(holder)).toBe('{}');
    });

    it('is stable on its own output', () => {
      const once = redactCopy({ token: credential(), wire: credential().serialize() });

      expect(redactCopy(once)).toEqual(once);
    });
  });

  describe('what it never does', () => {
    it('does not mutate the input', () => {
      const entity = new UserEntity(1, sensitive('email'), credential('api_key'));
      const wire = credential('token').serialize();
      const body = { entity, wire, list: [credential()] };

      redactCopy(body);

      expect(body.entity.apiKey).toBeInstanceOf(SensitiveString);
      expect(body.entity.apiKey.reveal()).toBe(CANARY);
      expect(body.wire.value).toBe(CANARY);
      expect(body.list[0]).toBeInstanceOf(SensitiveString);
    });

    it('CANARY: the JSON form of the copy contains no raw value', () => {
      const shared = { email: sensitive('email') };
      const body = {
        entity: new UserEntity(1, sensitive('email'), credential('api_key')),
        wire: credential('token').serialize(),
        nested: { deeper: { list: [credential(), { wire: sensitive().serialize() }] } },
        author: shared,
        reviewer: shared,
        map: new Map([['k', 'v']]),
        when: new Date(0),
      };

      const json = JSON.stringify(redactCopy(body));

      expect(json).not.toContain(CANARY);
      expect(json).toContain('[REDACTED:credential]');
      expect(json).toContain('[REDACTED:sensitive]');
    });
  });
});
