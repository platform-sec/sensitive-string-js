import { beforeEach, describe, expect, it } from 'vitest';
import {
  registerPolicy,
  resetPolicies,
  SensitiveString,
  sensitiveTemplate,
  st,
  withRevealContext,
} from './index.js';
import type { ISensitiveString } from './index.js';

describe('sensitiveTemplate', () => {
  beforeEach(() => {
    resetPolicies();
  });

  describe('assembly', () => {
    it('builds a protected value from a template literal', () => {
      const secret = new SensitiveString('secret123', 'credential', 'api_key');
      const result = st`API key: ${secret}`;

      expect(result).toBeInstanceOf(SensitiveString);
      expect(result.klass).toBe('credential');
      expect(result.reveal()).toBe('API key: secret123');
    });

    it('interleaves parts and interpolations in source order', () => {
      const first = new SensitiveString('secret1', 'credential', 'key1');
      const second = new SensitiveString('secret2', 'credential', 'key2');
      const third = new SensitiveString('data', 'sensitive', 'data');

      expect(st`${first}, ${second}, ${third}`.reveal()).toBe('secret1, secret2, data');
      expect(st`a${first}b`.reveal()).toBe('asecret1b');
    });

    it('coerces string, number, and boolean interpolations', () => {
      const result = st`Number: ${42}, Bool: ${true}, String: ${'text'}`;

      expect(result.reveal()).toBe('Number: 42, Bool: true, String: text');
    });

    it('mixes protected and plain interpolations', () => {
      const secret = new SensitiveString('secret', 'credential', 'key');
      const result = st`Value: ${'public'}, Number: ${42}, Secret: ${secret}`;

      expect(result.klass).toBe('credential');
      expect(result.reveal()).toBe('Value: public, Number: 42, Secret: secret');
    });

    it('defaults to the sensitive class without protected interpolations', () => {
      const empty = st``;
      const literal = st`Just a plain string`;
      const plain = st`Plain: ${'value'}, Number: ${42}`;

      for (const result of [empty, literal, plain]) {
        expect(result).toBeInstanceOf(SensitiveString);
        expect(result.klass).toBe('sensitive');
      }

      expect(empty.reveal()).toBe('');
      expect(literal.reveal()).toBe('Just a plain string');
      expect(plain.reveal()).toBe('Plain: value, Number: 42');
    });

    it('preserves unicode, newlines, and whitespace', () => {
      const secret = new SensitiveString('秘密', 'credential', 'key');
      const result = st`🔐 Secret: ${secret} 🔒`;

      const multiline = st`Line 1
  Secret: ${new SensitiveString('secret', 'credential')}
  Line 3`;

      expect(result.reveal()).toBe('🔐 Secret: 秘密 🔒');
      expect(multiline.reveal()).toContain('\n');
      expect(multiline.reveal()).toContain('  Secret: secret');
    });

    it('handles very long templates', () => {
      const secret = new SensitiveString('secret', 'credential', 'key');
      const long = 'x'.repeat(10000);

      expect(st`${long}${secret}${long}`.reveal().length).toBe(20006);
    });
  });

  describe('class inheritance', () => {
    it('inherits the most restrictive class regardless of order', () => {
      const sensitive = new SensitiveString('data', 'sensitive', 'data');
      const credential = new SensitiveString('secret', 'credential', 'secret');

      expect(st`${sensitive} and ${credential}`.klass).toBe('credential');
      expect(st`${credential} and ${sensitive}`.klass).toBe('credential');
    });

    it('uses the same combineClasses hook as concat()', () => {
      registerPolicy(
        {
          name: 'sensitive',
          redact: () => '[REDACTED:sensitive]',
          combineClasses: () => 'credential',
        },
        { overwrite: true }
      );

      const a = new SensitiveString('a', 'sensitive', 'a');
      const b = new SensitiveString('b', 'sensitive', 'b');

      expect(st`${a}${b}`.klass).toBe('credential');
      expect(new SensitiveString('', 'sensitive').concat(a).concat(b).klass).toBe('credential');
    });
  });

  describe('options form', () => {
    it('tightens the class and sets a label', () => {
      const sensitive = new SensitiveString('data', 'sensitive', 'data');

      const result = sensitiveTemplate({
        klass: 'credential',
        label: 'custom_label',
      })`Value: ${sensitive}`;

      expect(result.klass).toBe('credential');
      expect(result.label).toBe('custom_label');
      expect(result.reveal()).toBe('Value: data');
    });

    it('accepts a class equal to the inherited one', () => {
      const credential = new SensitiveString('secret', 'credential', 'key');

      expect(sensitiveTemplate({ klass: 'credential' })`key=${credential}`.klass).toBe(
        'credential'
      );
    });

    it('does not infer a label from the interpolations', () => {
      const secret = new SensitiveString('secret', 'credential', 'api_key');

      expect(st`key=${secret}`.label).toBeUndefined();
      expect(sensitiveTemplate({ label: 'api_url' })`key=${secret}`.label).toBe('api_url');
    });

    it('reuses a configured tag across calls', () => {
      const tag = sensitiveTemplate({ label: 'api_url' });
      const first = new SensitiveString('one', 'sensitive', 'first');
      const second = new SensitiveString('two', 'credential', 'second');

      expect(tag`a=${first}`.reveal()).toBe('a=one');
      expect(tag`a=${first}`.klass).toBe('sensitive');
      expect(tag`b=${second}`.reveal()).toBe('b=two');
      expect(tag`b=${second}`.klass).toBe('credential');
    });
  });

  describe('reveal context', () => {
    it('audits each interpolated value once with the provided context', () => {
      const audited: ISensitiveString[] = [];
      const secret = new SensitiveString('secret', 'credential', 'key');

      const result = sensitiveTemplate({
        ctx: { name: 'test-context', auditReveal: (value) => audited.push(value) },
      })`Value: ${secret}`;

      expect(audited).toEqual([secret]);
      expect(result.reveal()).toBe('Value: secret');
    });

    it('inherits the ambient reveal context', () => {
      const audited: ISensitiveString[] = [];
      const secret = new SensitiveString('secret', 'credential', 'key');

      withRevealContext(
        { name: 'global-context', auditReveal: (value) => audited.push(value) },
        () => {
          st`Value: ${secret}`;
        }
      );

      expect(audited).toEqual([secret]);
    });

    it('audits only the protected interpolations', () => {
      const audited: ISensitiveString[] = [];
      const first = new SensitiveString('a', 'credential', 'k1');
      const second = new SensitiveString('b', 'sensitive', 'k2');

      sensitiveTemplate({
        ctx: { name: 'audit', auditReveal: (value) => audited.push(value) },
      })`${first}/${'plain'}/${second}`;

      expect(audited).toEqual([first, second]);
    });
  });

  describe('interoperation with other operations', () => {
    it('accepts the result of one template inside another', () => {
      const first = new SensitiveString('secret1', 'credential', 'key1');
      const second = new SensitiveString('secret2', 'sensitive', 'key2');

      const inner = st`Inner: ${second}`;
      const outer = st`Outer: ${first}, ${inner}`;

      expect(outer.klass).toBe('credential');
      expect(outer.reveal()).toBe('Outer: secret1, Inner: secret2');
    });

    it('composes with concat() and map()', () => {
      const first = new SensitiveString('secret1', 'credential', 'key1');
      const second = new SensitiveString('secret2', 'credential', 'key2');

      const joined = st`First: ${first}`.concat(st` Second: ${second}`);
      const mapped = st`Message: ${new SensitiveString('hello', 'credential')}`.map((value) =>
        value.toUpperCase()
      );

      expect(joined.klass).toBe('credential');
      expect(joined.reveal()).toBe('First: secret1 Second: secret2');
      expect(mapped.reveal()).toBe('MESSAGE: HELLO');
    });

    it('works in an async context', async () => {
      const secret = new SensitiveString('secret', 'credential', 'key');
      const result = await Promise.resolve(st`Async: ${secret}`);

      expect(result).toBeInstanceOf(SensitiveString);
      expect(result.reveal()).toBe('Async: secret');
    });
  });
});
