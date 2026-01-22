/**
 * Serialization Path Fuzzing Tests
 *
 * Tests all serialization paths with various inputs to catch edge cases
 * that might leak sensitive values.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import * as util from 'node:util';
import { SensitiveString, SensitivityClass, resetPolicies } from '../index.js';

// Fuzzing corpus - values that might trigger edge cases
// Note: Values must be unique enough to not appear naturally in output
// (e.g., avoid single chars, whitespace-only, or common words like 'undefined')
const FUZZ_VALUES = [
  // Basic
  'simple_secret',
  // Empty (special case - handled separately in tests)
  '',
  // Unicode
  '密码123',
  'пароль🔐',
  'مرور',
  'パスワード',
  '🔐🔑🗝️',
  // Emoji edge cases
  '👨‍👩‍👧‍👦', // Family emoji (compound)
  '🏳️‍🌈', // Flag with modifier
  // Special characters
  '<script>alert(1)</script>',
  '${process.env.SECRET}',
  '{{template}}',
  '%s%s%s%s',
  '\x00\x01\x02',
  // Escape sequences
  '\\n\\t\\r',
  '\\"quoted\\"',
  "it's a test",
  // Length edge cases (use unique prefixes to avoid false positives)
  'secret_xyz_test',
  'secret_'.repeat(100),
  'secret_'.repeat(1000),
  // JSON-like
  '{"nested": "value"}',
  '"quoted"',
  '[1,2,3]',
  // Prototype pollution attempts (use unique prefixes)
  'secret___proto___test',
  'secret_constructor_test',
  'secret_prototype_test',
  // Path traversal
  '../../../etc/passwd',
  '..\\..\\..\\windows\\system32',
  // SQL injection
  "'; DROP TABLE users; --",
  '1 OR 1=1',
  // Format string
  '%d%s%n%x',
  // Numeric-like with unique prefix
  'secret_123_test',
  'secret_123.456_test',
  // RegExp special chars
  '.*+?^${}()|[]\\',
  // HTML entities
  '&lt;&gt;&amp;&quot;',
  // Base64-like
  'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=',
  // JWT-like
  'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature',
  // UUID-like
  '550e8400-e29b-41d4-a716-446655440000',
  // API key patterns
  'sk-proj-abc123def456',
  'pk_test_abc123',
  'Bearer abc123',
];

// Values that would cause false positives due to appearing naturally in output
// These are tested separately with targeted assertions
const PROBLEMATIC_VALUES = [
  ' ',      // Whitespace appears in util.inspect output
  '   ',
  '\t\n\r',
  '\t',
  '\n',
  'x',      // Single chars can appear in paths/stack traces
  'xy',
  'xyz',
  'null',         // These words appear in JavaScript output
  'undefined',
  'true',
  'false',
  '123',
  'NaN',
  'Infinity',
  '-Infinity',
  '__proto__',    // These appear in prototype-related output
  'constructor',
  'prototype',
  '__defineGetter__',
  '__defineSetter__',
];

const ALL_CLASSES: SensitivityClass[] = ['credential', 'sensitive'];

describe('Serialization Path Security', () => {
  beforeEach(() => {
    resetPolicies();
  });

  for (const klass of ALL_CLASSES) {
    describe(`${klass} class`, () => {
      for (const value of FUZZ_VALUES) {
        const displayValue =
          value.length > 20
            ? `${value.slice(0, 20)}... (${value.length} chars)`
            : value || '(empty)';

        describe(`with value: ${displayValue}`, () => {
          it('toString() never leaks', () => {
            const s = new SensitiveString(value, klass);
            const result = s.toString();
            if (value.length > 0) {
              expect(result).not.toContain(value);
            }
            expect(result).toMatch(/\[REDACTED/);
          });

          it('toJSON() never leaks', () => {
            const s = new SensitiveString(value, klass);
            const result = JSON.stringify(s);
            if (value.length > 0) {
              expect(result).not.toContain(value);
            }
          });

          it('util.inspect() never leaks', () => {
            const s = new SensitiveString(value, klass);
            const result = util.inspect(s);
            if (value.length > 0) {
              expect(result).not.toContain(value);
            }
          });

          it('util.inspect() with depth never leaks', () => {
            const s = new SensitiveString(value, klass);
            const result = util.inspect({ nested: { deep: s } }, { depth: 10 });
            if (value.length > 0) {
              expect(result).not.toContain(value);
            }
          });

          it('util.inspect() with showHidden never leaks', () => {
            const s = new SensitiveString(value, klass);
            const result = util.inspect(s, { showHidden: true });
            if (value.length > 0) {
              expect(result).not.toContain(value);
            }
          });

          it('Object.keys/values/entries never leak', () => {
            const s = new SensitiveString(value, klass);
            const keys = Object.keys(s).join('');
            const values = Object.values(s).map(String).join('');
            const entries = Object.entries(s).flat().map(String).join('');

            if (value.length > 0) {
              expect(keys).not.toContain(value);
              expect(values).not.toContain(value);
              expect(entries).not.toContain(value);
            }
          });

          it('spread operator never leaks', () => {
            const s = new SensitiveString(value, klass);
            const spread = { ...s };
            const result = JSON.stringify(spread);
            if (value.length > 0) {
              expect(result).not.toContain(value);
            }
          });

          it('Array methods never leak', () => {
            const s = new SensitiveString(value, klass);
            const arr = [s];
            const joined = arr.join(',');
            const mapped = arr.map(String).join('');
            const concatResult = arr.concat([]).map(String).join('');

            if (value.length > 0) {
              expect(joined).not.toContain(value);
              expect(mapped).not.toContain(value);
              expect(concatResult).not.toContain(value);
            }
          });

          it('String coercion never leaks', () => {
            const s = new SensitiveString(value, klass);
            const stringConstructor = String(s);
            const templateLiteral = `${s}`;
            const concatenated = '' + s;

            if (value.length > 0) {
              expect(stringConstructor).not.toContain(value);
              expect(templateLiteral).not.toContain(value);
              expect(concatenated).not.toContain(value);
            }
          });

          it('error stack traces never leak', () => {
            const s = new SensitiveString(value, klass);
            try {
              throw new Error(`Context: ${String(s)}`);
            } catch (e) {
              const stack = (e as Error).stack ?? '';
              const message = (e as Error).message;
              if (value.length > 0) {
                expect(stack).not.toContain(value);
                expect(message).not.toContain(value);
              }
            }
          });
        });
      }
    });
  }

  describe('nested structure serialization', () => {
    const CANARY = 'NESTED_CANARY_xyz789';

    it('JSON.stringify handles deeply nested SensitiveString', () => {
      const nested = {
        level1: {
          level2: {
            level3: {
              level4: {
                secret: new SensitiveString(CANARY, 'credential'),
              },
            },
          },
        },
      };

      const result = JSON.stringify(nested);
      expect(result).not.toContain(CANARY);
    });

    it('JSON.stringify handles array of SensitiveStrings', () => {
      const arr = [
        new SensitiveString(CANARY + '1', 'credential'),
        new SensitiveString(CANARY + '2', 'credential'),
        new SensitiveString(CANARY + '3', 'credential'),
      ];

      const result = JSON.stringify(arr);
      expect(result).not.toContain(CANARY);
    });

    it('JSON.stringify handles mixed nested structure', () => {
      const mixed = {
        users: [
          {
            name: 'Alice',
            password: new SensitiveString(CANARY, 'credential'),
            tokens: [
              new SensitiveString(CANARY + '_token1', 'credential'),
              new SensitiveString(CANARY + '_token2', 'credential'),
            ],
          },
        ],
        config: {
          apiKey: new SensitiveString(CANARY + '_api', 'credential'),
        },
      };

      const result = JSON.stringify(mixed);
      expect(result).not.toContain(CANARY);
    });

    it('JSON.stringify with replacer does not leak', () => {
      const s = new SensitiveString(CANARY, 'credential');
      const obj = { secret: s, public: 'visible' };

      // Malicious replacer trying to access internals
      const result = JSON.stringify(obj, (key, value) => {
        if (typeof value === 'object' && value !== null) {
          return { ...value, _inspected: true };
        }
        return value;
      });

      expect(result).not.toContain(CANARY);
    });

    it('JSON.stringify with space parameter does not leak', () => {
      const obj = {
        secret: new SensitiveString(CANARY, 'credential'),
      };

      const result = JSON.stringify(obj, null, 2);
      expect(result).not.toContain(CANARY);
    });
  });

  describe('util.inspect edge cases', () => {
    const CANARY = 'INSPECT_CANARY_abc123';

    it('handles various inspect options', () => {
      const s = new SensitiveString(CANARY, 'credential');

      const options = [
        {},
        { depth: 0 },
        { depth: Infinity },
        { colors: true },
        { colors: false },
        { showHidden: true },
        { showHidden: false },
        { maxArrayLength: 100 },
        { maxStringLength: 100 },
        { breakLength: 80 },
        { compact: true },
        { compact: false },
        { sorted: true },
        { getters: true },
        { getters: 'get' as const },
        { getters: 'set' as const },
      ];

      for (const opts of options) {
        const result = util.inspect(s, opts);
        expect(result).not.toContain(CANARY);
      }
    });

    it('handles custom inspect in nested objects', () => {
      const nested = {
        data: {
          secret: new SensitiveString(CANARY, 'credential'),
        },
        [Symbol.for('nodejs.util.inspect.custom')]() {
          return 'CustomObject';
        },
      };

      const result = util.inspect(nested, { depth: 10 });
      expect(result).not.toContain(CANARY);
    });
  });

  describe('console output simulation', () => {
    const CANARY = 'CONSOLE_CANARY_def456';

    it('console.log argument would not leak', () => {
      const s = new SensitiveString(CANARY, 'credential');

      // Simulate what console.log does internally
      const formatted = util.format('%s', s);
      expect(formatted).not.toContain(CANARY);

      const formatted2 = util.format('%o', s);
      expect(formatted2).not.toContain(CANARY);

      const formatted3 = util.format('%O', s);
      expect(formatted3).not.toContain(CANARY);

      const formatted4 = util.format('%j', s);
      expect(formatted4).not.toContain(CANARY);
    });

    it('console.dir would not leak', () => {
      const s = new SensitiveString(CANARY, 'credential');

      // console.dir uses util.inspect internally
      const result = util.inspect(s, { showHidden: false, depth: 2 });
      expect(result).not.toContain(CANARY);
    });
  });
});
