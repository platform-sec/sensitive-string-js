/**
 * Path-based wrapping and field classification.
 *
 * Both run at a decode boundary: something arrives as plain JSON and has to
 * become an object whose secret fields are wrapped. `wrapSensitiveByPath` deep
 * clones before it wraps, so its cost tracks the whole payload and not just
 * the configured paths, which is the fact the first group is here to show.
 *
 * The classification group prices the compiled form against `classifyField`,
 * which compiles the spec on every call. That gap is the argument for hoisting
 * `compileClassification` out of a per-field loop.
 */

import { bench, describe } from 'vitest';

import {
  checkSensitiveFieldsWrapped,
  unwrapSensitiveByPath,
  validateSensitiveFieldConfig,
  wrapSensitiveByPath,
} from '../wrap.js';
import { classifyField, compileClassification } from '../classification.js';
import type { ClassificationSpec } from '../classification.js';
import { benchFloor, consume, PAYLOAD_FIELDS, plainPayload, requestPayload } from './fixtures.js';

const plain = plainPayload();
const wrapped = requestPayload();

/** A wider payload, so the clone cost separates from the per-path cost. */
const widePlain = {
  ...plainPayload(),
  events: Array.from({ length: 50 }, (_unused, index) => ({
    at: 1_700_000_000_000 + index,
    kind: 'charge.updated',
    seq: index,
  })),
};

const SPEC: ClassificationSpec = {
  fields: {
    'auth.token': 'credential',
    'auth.refresh': 'credential',
    'user.email': 'sensitive',
  },
  rules: [
    { pattern: /secret|token|password/i, klass: 'credential' },
    { pattern: /email|phone|ssn/i, klass: 'sensitive' },
    { pattern: /^(id|seq|kind)$/i, klass: 'plain' },
  ],
  fallback: 'plain',
};

const compiled = compileClassification(SPEC);

/**
 * Four paths that match nothing, so the pair against `PAYLOAD_FIELDS` differs
 * only in whether the paths hit. One path against four measured the path
 * count rather than the wrapping.
 */
const MISSING_FIELDS = {
  'absent.one': 'sensitive',
  'absent.two': 'sensitive',
  'absent.three': 'credential',
  'absent.four': 'credential',
} as const;

/** Keys spanning every level of the precedence order: field, rule, fallback. */
const KEYS = ['auth.token', 'apiSecret', 'user.email', 'seq', 'unmatchedKeyName'] as const;

describe('wrapSensitiveByPath', () => {
  bench('structuredClone only (control)', () => {
    consume(structuredClone(plain));
  });

  bench('request payload, four paths', () => {
    consume(wrapSensitiveByPath(plain, PAYLOAD_FIELDS));
  });

  bench('request payload, four paths that match nothing', () => {
    consume(wrapSensitiveByPath(plain, MISSING_FIELDS));
  });

  bench('wide payload, four paths', () => {
    consume(wrapSensitiveByPath(widePlain, PAYLOAD_FIELDS));
  });
});

describe('unwrapSensitiveByPath', () => {
  bench('wrap', () => {
    consume(wrapSensitiveByPath(plain, PAYLOAD_FIELDS));
  });

  bench('unwrap', () => {
    consume(unwrapSensitiveByPath(wrapped, PAYLOAD_FIELDS));
  });

  bench('round trip', () => {
    consume(unwrapSensitiveByPath(wrapSensitiveByPath(plain, PAYLOAD_FIELDS), PAYLOAD_FIELDS));
  });
});

describe('config checks', () => {
  bench('validateSensitiveFieldConfig', () => {
    consume(validateSensitiveFieldConfig(plain, PAYLOAD_FIELDS));
  });

  bench('checkSensitiveFieldsWrapped, all wrapped', () => {
    consume(checkSensitiveFieldsWrapped(wrapped, PAYLOAD_FIELDS));
  });

  bench('checkSensitiveFieldsWrapped, none wrapped', () => {
    consume(checkSensitiveFieldsWrapped(plain, PAYLOAD_FIELDS));
  });
});

describe('classification, one key', () => {
  bench('compiled, exact field match', () => {
    consume(compiled.classify('auth.token'));
  });

  bench('compiled, rule match', () => {
    consume(compiled.classify('apiSecret'));
  });

  bench('compiled, falls through to the fallback', () => {
    consume(compiled.classify('unmatchedKeyName'));
  });

  bench('classifyField, compiles the spec each call', () => {
    consume(classifyField('apiSecret', SPEC));
  });
});

describe('classification, a whole payload of keys', () => {
  bench('compiled once, five keys', () => {
    for (const key of KEYS) {
      consume(compiled.classify(key));
    }
  });

  bench('compileClassification then five keys', () => {
    const fresh = compileClassification(SPEC);

    for (const key of KEYS) {
      consume(fresh.classify(key));
    }
  });

  bench('classifyField, five keys', () => {
    for (const key of KEYS) {
      consume(classifyField(key, SPEC));
    }
  });
});

benchFloor();
