import type { SensitiveFieldConfig } from '@platform-sec/sensitive-string-core';
import { describe, expect, it } from 'vitest';
import { compileNameFields, compilePathFields } from '../fields.js';

/**
 * Field maps are validated when a middleware is constructed, so these are the
 * failures an application sees at startup rather than on the request that
 * happens to carry the field.
 */
describe('compilePathFields', () => {
  it('defaults a label to the last path segment', () => {
    expect(compilePathFields({ 'creditCard.number': 'credential' }, 'sensitiveBody')).toEqual({
      'creditCard.number': { klass: 'credential', label: 'number' },
    });
  });

  it('keeps an explicit label', () => {
    expect(
      compilePathFields({ 'user.tax': { klass: 'sensitive', label: 'ssn' } }, 'sensitiveBody')
    ).toEqual({ 'user.tax': { klass: 'sensitive', label: 'ssn' } });
  });

  it('accepts an empty map', () => {
    expect(compilePathFields({}, 'sensitiveBody')).toEqual({});
  });

  it('rejects a map that is not an object', () => {
    expect(() =>
      compilePathFields(null as unknown as SensitiveFieldConfig, 'sensitiveBody')
    ).toThrow(/must be an object/);
    expect(() =>
      compilePathFields('credential' as unknown as SensitiveFieldConfig, 'sensitiveBody')
    ).toThrow(/must be an object/);
  });

  it('names the offending path and the value it received', () => {
    expect(() =>
      compilePathFields({ password: null as unknown as 'credential' }, 'sensitiveBody')
    ).toThrow(/sensitiveBody\.fields\['password'\].*received null/s);
    expect(() =>
      compilePathFields({ password: { klass: 'nope' } as unknown as 'credential' }, 'sensitiveBody')
    ).toThrow(/received \{"klass":"nope"\}/);
    expect(() =>
      compilePathFields({ password: 42 as unknown as 'credential' }, 'sensitiveBody')
    ).toThrow(/received number/);
  });

  it('rejects every reserved path segment', () => {
    for (const segment of ['__proto__', 'constructor', 'prototype']) {
      expect(() => compilePathFields({ [`a.${segment}.b`]: 'sensitive' }, 'sensitiveBody')).toThrow(
        /reserved segment/
      );
    }
  });
});

describe('compileNameFields', () => {
  it('lower-cases the name and labels with it', () => {
    expect(compileNameFields({ 'X-Api-Key': 'credential' }, 'sensitiveHeaders')).toEqual({
      'x-api-key': { klass: 'credential', label: 'x-api-key' },
    });
  });

  it('does not treat a dot in a name as a path separator', () => {
    // Nothing walks a path here, so a name is only checked for being non-empty.
    expect(compileNameFields({ 'x.weird.name': 'sensitive' }, 'sensitiveHeaders')).toEqual({
      'x.weird.name': { klass: 'sensitive', label: 'x.weird.name' },
    });
  });

  it('rejects two names that differ only in case', () => {
    // Both name the same header, and the later one would otherwise silently
    // replace the class the earlier one declared.
    expect(() =>
      compileNameFields({ 'X-Api-Key': 'credential', 'x-api-key': 'sensitive' }, 'sensitiveHeaders')
    ).toThrow(/declares 'x-api-key' more than once/);
  });

  it('rejects an empty name', () => {
    expect(() => compileNameFields({ '': 'credential' }, 'sensitiveHeaders')).toThrow(
      /empty header name/
    );
  });
});
