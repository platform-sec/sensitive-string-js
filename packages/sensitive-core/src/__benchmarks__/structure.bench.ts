/**
 * The structure walkers.
 *
 * `redactInStructure`, `safeStringify`, `redactCopy` and the two detectors all
 * traverse an arbitrary payload, so their cost scales with the payload rather
 * than with the value, and they are what a logging middleware runs on every
 * request. This is the file to read when a service reports that logging got
 * expensive.
 *
 * Each group holds a plain-payload control of the same shape. The gap between
 * the two is the price of redaction; the control itself is the price of the
 * walk, which a caller pays whether or not anything sensitive is present.
 */

import { bench, describe } from 'vitest';

import {
  containsSensitive,
  redactInStructure,
  safeLog,
  safeStringify,
  sensitiveClassesIn,
  createSensitiveSerializer,
} from '../redact.js';
import { redactCopy } from '../redact-copy.js';
import { consume, consumeFlag, nestedPayload, plainPayload, recordList, requestPayload } from './fixtures.js';

const payload = requestPayload();
const plain = plainPayload();

const smallList = recordList(10);
const mediumList = recordList(100);
const largeList = recordList(1000);

const shallow = nestedPayload(2);
const deep = nestedPayload(32);

describe('redactInStructure', () => {
  bench('request payload, no sensitive values (control)', () => {
    consume(redactInStructure(plain));
  });

  bench('request payload', () => {
    consume(redactInStructure(payload));
  });

  bench('nested 2 deep', () => {
    consume(redactInStructure(shallow));
  });

  bench('nested 32 deep', () => {
    consume(redactInStructure(deep));
  });
});

describe('redactInStructure by collection size', () => {
  bench('10 records', () => {
    consume(redactInStructure(smallList));
  });

  bench('100 records', () => {
    consume(redactInStructure(mediumList));
  });

  bench('1000 records', () => {
    consume(redactInStructure(largeList));
  });
});

describe('redactCopy against redactInStructure', () => {
  bench('redactInStructure, request payload', () => {
    consume(redactInStructure(payload));
  });

  bench('redactCopy, request payload', () => {
    consume(redactCopy(payload));
  });

  bench('redactInStructure, 100 records', () => {
    consume(redactInStructure(mediumList));
  });

  bench('redactCopy, 100 records', () => {
    consume(redactCopy(mediumList));
  });
});

describe('stringify', () => {
  const serializer = createSensitiveSerializer();

  bench('JSON.stringify, plain payload (control)', () => {
    consume(JSON.stringify(plain));
  });

  bench('JSON.stringify, sensitive payload', () => {
    consume(JSON.stringify(payload));
  });

  bench('safeStringify', () => {
    consume(safeStringify(payload));
  });

  bench('safeStringify, pretty', () => {
    consume(safeStringify(payload, { pretty: true }));
  });

  bench('JSON.stringify with a sensitive serializer', () => {
    consume(JSON.stringify(payload, (_key, value) => serializer(value)));
  });
});

describe('safeLog', () => {
  bench('plain payload (control)', () => {
    consume(safeLog(plain));
  });

  bench('request payload', () => {
    consume(safeLog(payload));
  });

  bench('100 records', () => {
    consume(safeLog(mediumList));
  });
});

describe('detection', () => {
  bench('containsSensitive, plain payload', () => {
    consumeFlag(containsSensitive(plain));
  });

  bench('containsSensitive, request payload', () => {
    consumeFlag(containsSensitive(payload));
  });

  bench('containsSensitive, 100 records', () => {
    consumeFlag(containsSensitive(mediumList));
  });

  bench('sensitiveClassesIn, request payload', () => {
    consume(sensitiveClassesIn(payload));
  });

  bench('sensitiveClassesIn, 100 records', () => {
    consume(sensitiveClassesIn(mediumList));
  });
});

describe('detection against redaction', () => {
  // A middleware that checks before it redacts pays both. The point of the
  // group is whether the check is cheap enough to be worth making first.
  bench('containsSensitive only', () => {
    consumeFlag(containsSensitive(payload));
  });

  bench('redactInStructure only', () => {
    consume(redactInStructure(payload));
  });

  bench('containsSensitive then redactInStructure', () => {
    consume(containsSensitive(payload) ? redactInStructure(payload) : payload);
  });
});
