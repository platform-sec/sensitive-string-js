import { describe, it, expect } from 'vitest';
import safeRegex from 'safe-regex2';

import { DECLARED_FALLBACK, allSpec, jsonSpec } from './classify.js';
import {
  DISCLOSING_LABEL_PATTERNS,
  describeLabelDisclosure,
  fieldLabel,
  logicalLabel,
} from './label.js';

describe('jsonSpec', () => {
  it('defaults an undeclared key to credential', () => {
    const spec = jsonSpec({ fields: { username: 'sensitive' } });

    expect(DECLARED_FALLBACK).toBe('credential');
    expect(spec.classify('new_field')).toBe('credential');
  });

  it('lets a caller widen the fallback deliberately', () => {
    const spec = jsonSpec({ fields: { username: 'sensitive' }, fallback: 'plain' });

    expect(spec.classify('new_field')).toBe('plain');
  });

  it('keeps declared fields above rules', () => {
    const spec = jsonSpec({
      fields: { password: 'sensitive' },
      rules: [{ pattern: /password/, klass: 'credential' }],
    });

    expect(spec.classify('password')).toBe('sensitive');
  });
});

describe('allSpec', () => {
  it('requires an explicit fallback', () => {
    expect(() => allSpec({} as unknown as { fallback: 'plain' })).toThrow(
      /getAll requires an explicit fallback/
    );
  });

  it('names both sensible answers in the error, since only the caller knows', () => {
    let message = '';

    try {
      allSpec({} as unknown as { fallback: 'plain' });
    } catch (error) {
      message = (error as Error).message;
    }

    expect(message).toContain('plain');
    expect(message).toContain('credential');
  });

  it('applies the fallback the caller chose', () => {
    expect(allSpec({ fallback: 'plain' }).classify('LOG_LEVEL')).toBe('plain');
    expect(allSpec({ fallback: 'credential' }).classify('anything')).toBe('credential');
  });

  it('takes rules over the fallback', () => {
    const spec = allSpec({
      rules: [{ pattern: /_KEY$/, klass: 'credential' }],
      fallback: 'plain',
    });

    expect(spec.classify('API_KEY')).toBe('credential');
    expect(spec.classify('LOG_LEVEL')).toBe('plain');
  });
});

describe('the patterns this package ships', () => {
  it('has no pattern with exponential backtracking', () => {
    for (const { name, pattern } of DISCLOSING_LABEL_PATTERNS) {
      expect(safeRegex(pattern), `${name} is not safe`).toBe(true);
    }
  });
});

describe('logicalLabel', () => {
  it('strips a scheme and authority', () => {
    expect(logicalLabel('https://vault.internal:8200/v1/kv/data/prod/db')).toBe(
      'v1/kv/data/prod/db'
    );
  });

  it('strips a leading slash', () => {
    expect(logicalLabel('/api/v1/namespaces/payments/secrets/db-creds')).toBe(
      'api/v1/namespaces/payments/secrets/db-creds'
    );
  });

  it('strips a query string and a fragment', () => {
    expect(logicalLabel('prod/db?version=7')).toBe('prod/db');
    expect(logicalLabel('prod/db#password')).toBe('prod/db');
  });

  it('leaves an ordinary logical path alone', () => {
    expect(logicalLabel('kv/prod/db')).toBe('kv/prod/db');
  });
});

describe('fieldLabel', () => {
  it('keeps the field name attached to the path', () => {
    expect(fieldLabel('prod/db', 'password')).toBe('prod/db#password');
  });
});

describe('describeLabelDisclosure', () => {
  it.each([
    ['arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf', 'AWS ARN'],
    ['https://contoso-prod.vault.azure.net/secrets/db-password/a1b2c3', 'scheme and authority'],
    ['projects/481516234299/secrets/db-password/versions/7', 'GCP project number'],
    ['ocid1.vaultsecret.oc1.iad.amaaaa', 'OCID'],
    ['vault.internal:8200/v1/kv/data/prod/db', 'host and port'],
  ])('flags %s', (label, rule) => {
    expect(describeLabelDisclosure(label)).toContain(rule);
  });

  it.each(['prod/db', 'db-password', 'payments/db-creds', 'kv/prod/db', 'secrets.enc.yaml'])(
    'passes the label the rule asks for: %s',
    (label) => {
      expect(describeLabelDisclosure(label)).toEqual([]);
    }
  );
});
