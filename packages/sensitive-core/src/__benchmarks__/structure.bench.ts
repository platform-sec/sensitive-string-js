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
import {
  benchFloor,
  consume,
  consumeFlag,
  nestedPayload,
  plainPayload,
  plainRecordList,
  recordList,
  recordListWrappedLast,
  requestPayload,
} from './fixtures.js';

const payload = requestPayload();
const plain = plainPayload();

const smallList = recordList(10);
const mediumList = recordList(100);
const largeList = recordList(1000);

const smallPlainList = plainRecordList(10);
const mediumPlainList = plainRecordList(100);
const largePlainList = plainRecordList(1000);

const largeListWrappedLast = recordListWrappedLast(1000);

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

/**
 * What a response filter costs, which is the walk this package runs that nobody
 * asked for by name.
 *
 * `redactInStructure` is called by application code, on a payload the
 * application chose. `redactCopy` is called by the Express, Fastify and NestJS
 * response filters on every JSON body they send, so the size is chosen by
 * whatever the endpoint returns. A thousand-row result page is an ordinary
 * thing for an endpoint to return and a large thing for a filter to walk, and
 * this group is where that shows up.
 *
 * Read the plain rows against the wrapped rows of the same size rather than
 * against each other. The gap is what redaction costs; the plain row itself is
 * what the walk costs, and that is the part every response pays in order to
 * establish that it was carrying nothing.
 *
 * That share is not constant, and the way it moves is the useful part: measured
 * on Node 22.15.0 the plain walk was a little over half the total at 100
 * records and about three quarters of it at 1000. Redaction is per wrapped
 * value and the walk is per node, so the larger the collection the more of the
 * bill belongs to the traversal rather than to anything this library was asked
 * to hide. A route returning a thousand rows is mostly paying to be looked at.
 */
describe('redactCopy by collection size', () => {
  bench('10 records', () => {
    consume(redactCopy(smallList));
  });

  bench('10 records, nothing sensitive (control)', () => {
    consume(redactCopy(smallPlainList));
  });

  bench('100 records', () => {
    consume(redactCopy(mediumList));
  });

  bench('100 records, nothing sensitive (control)', () => {
    consume(redactCopy(mediumPlainList));
  });

  bench('1000 records', () => {
    consume(redactCopy(largeList));
  });

  bench('1000 records, nothing sensitive (control)', () => {
    consume(redactCopy(largePlainList));
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

/**
 * The same question over a collection, where the answer depends on the payload
 * rather than on the code.
 *
 * The group above asks whether checking first is worth it and answers for one
 * small payload. Over a collection there is no single answer, because
 * `containsSensitive` returns on its first hit and therefore costs whatever the
 * distance to that hit is. Three shapes, and they disagree with each other:
 *
 * Nothing sensitive, the common case for a response body, is where checking
 * first wins. The check walks, finds nothing, and the original object is
 * returned, so the copy is never allocated at all.
 *
 * Everything sensitive is roughly a wash. The check answers off the first
 * record and the copy then does the whole walk anyway.
 *
 * One sensitive value in the last record is where checking first loses, and it
 * loses by more than the other two win: a full walk to find the hit, then a full
 * walk to copy.
 *
 * Ratios rather than figures, because these were confirmed on two harnesses
 * that disagree on absolutes by about a factor of two and agree closely on the
 * gaps. Checking first came out 1.4x to 1.5x faster with nothing sensitive and
 * 1.8x slower with the one wrapped value last, on both. On the all-wrapped
 * shape the two harnesses disagree about which side wins by a few percent,
 * which is what makes it a wash rather than a result.
 *
 * So the strategy is a bet on the shape of the payload and not an optimisation,
 * which is the reason this library does not make it on a caller's behalf. An
 * integration that knows its own responses can take the bet with these figures
 * in front of it.
 */
describe('detection against redaction, by where the hit is', () => {
  bench('1000 plain records, copy always', () => {
    consume(redactCopy(largePlainList));
  });

  bench('1000 plain records, check first', () => {
    consume(containsSensitive(largePlainList) ? redactCopy(largePlainList) : largePlainList);
  });

  bench('1000 wrapped records, copy always', () => {
    consume(redactCopy(largeList));
  });

  bench('1000 wrapped records, check first', () => {
    consume(containsSensitive(largeList) ? redactCopy(largeList) : largeList);
  });

  bench('1000 records, last one wrapped, copy always', () => {
    consume(redactCopy(largeListWrappedLast));
  });

  bench('1000 records, last one wrapped, check first', () => {
    consume(
      containsSensitive(largeListWrappedLast)
        ? redactCopy(largeListWrappedLast)
        : largeListWrappedLast
    );
  });
});

benchFloor();
