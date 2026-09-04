import { describe, it, expect } from 'vitest';

import { crc32c, toChecksum } from './crc32c.js';

describe('crc32c', () => {
  it('matches the standard check vector', () => {
    // The value every CRC32C implementation is checked against.
    expect(crc32c(new TextEncoder().encode('123456789'))).toBe(0xe306_9283);
  });

  it('is zero for an empty input', () => {
    expect(crc32c(new Uint8Array(0))).toBe(0);
  });

  it('differs for inputs that differ by one bit', () => {
    const a = crc32c(new TextEncoder().encode('secret'));
    const b = crc32c(new TextEncoder().encode('secreu'));

    expect(a).not.toBe(b);
  });

  it('stays unsigned for inputs whose CRC has the high bit set', () => {
    for (const text of ['a', 'ab', 'abc', 'the quick brown fox', 'x'.repeat(1000)]) {
      expect(crc32c(new TextEncoder().encode(text))).toBeGreaterThanOrEqual(0);
    }
  });
});

describe('toChecksum', () => {
  it('accepts a number', () => {
    expect(toChecksum(0xe306_9283)).toBe(0xe306_9283);
  });

  it('accepts a decimal string, which is how gax delivers a large int64', () => {
    expect(toChecksum('3808858755')).toBe(0xe306_9283);
  });

  it('accepts a protobufjs Long', () => {
    expect(toChecksum({ low: 0xe306_9283 | 0, high: 0, unsigned: true })).toBe(0xe306_9283);
  });

  it('accepts a Long that stringifies rather than exposing its words', () => {
    expect(toChecksum({ toString: () => '3808858755' })).toBe(0xe306_9283);
  });

  it('reports an unrecognized shape as absent rather than as zero', () => {
    // Reporting zero would make the comparison fail for every payload; ignoring
    // an unrecognized shape silently would make the check pass for every one.
    // Absent is the third answer and the only honest one.
    expect(toChecksum(undefined)).toBeUndefined();
    expect(toChecksum(null)).toBeUndefined();
    expect(toChecksum('not a number')).toBeUndefined();
    expect(toChecksum({ low: 1, high: 12345 })).toBeUndefined();
  });
});
