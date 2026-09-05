/**
 * The winston format.
 *
 * A format transform runs once per log record, on the logger's hot path, so
 * what matters here is the cost added to a record that holds nothing sensitive
 * at all. That is the common case in a service that installs the format
 * globally, and it is the first group.
 *
 * `stampClasses` and `dropClasses` both collect the classes present, which is
 * a second walk of the record. The last group prices that against the plain
 * redaction the format does by default.
 */

import { bench, describe } from 'vitest';

import { sensitiveFormat } from '../winston.js';
import type { WinstonInfo } from '../winston.js';
import { benchFloor, consume, plainPayload, requestPayload } from './fixtures.js';

/**
 * The late-install warning is suppressed throughout. It fires once per format
 * and calls `process.emitWarning`, which would land in the middle of a run and
 * measure the warning rather than the transform.
 */
const format = sensitiveFormat({ warnOnLateInstall: false });
const stamping = sensitiveFormat({ warnOnLateInstall: false, stampClasses: true });
const dropping = sensitiveFormat({
  warnOnLateInstall: false,
  dropClasses: ['credential'],
});
const noSplat = sensitiveFormat({ warnOnLateInstall: false, redactSplat: false });

const SPLAT = Symbol.for('splat');

/**
 * Records are rebuilt per iteration on purpose. The transform assigns redacted
 * copies onto the record it is given, so a shared object would arrive already
 * redacted after the first call and every later iteration would measure a
 * different, cheaper operation.
 */
function sensitiveRecord(): WinstonInfo {
  return { level: 'info', message: 'charge created', ...requestPayload() };
}

function plainRecord(): WinstonInfo {
  return { level: 'info', message: 'charge created', ...plainPayload() };
}

function splatRecord(): WinstonInfo {
  const record = sensitiveRecord();
  record[SPLAT] = [requestPayload()];
  return record;
}

describe('transform', () => {
  // Each transform is paired with a control that builds the same record and
  // does nothing else. Rebuilding is not optional here, so the transform cost
  // is the gap within a pair; comparing across pairs measures the record.
  bench('plain record, built only (control)', () => {
    consume(plainRecord());
  });

  bench('plain record, transformed', () => {
    consume(format.transform(plainRecord()));
  });

  bench('sensitive record, built only (control)', () => {
    consume(sensitiveRecord());
  });

  bench('sensitive record, transformed', () => {
    consume(format.transform(sensitiveRecord()));
  });
});

describe('transform, no payload', () => {
  bench('bare record, built only (control)', () => {
    consume({ level: 'info', message: 'ready' });
  });

  bench('bare record, transformed', () => {
    consume(format.transform({ level: 'info', message: 'ready' }));
  });
});

describe('splat handling', () => {
  bench('record built only (control)', () => {
    consume(splatRecord());
  });

  bench('splat redacted', () => {
    consume(format.transform(splatRecord()));
  });

  bench('splat left alone', () => {
    consume(noSplat.transform(splatRecord()));
  });
});

describe('class collection', () => {
  bench('record built only (control)', () => {
    consume(sensitiveRecord());
  });

  bench('redact only', () => {
    consume(format.transform(sensitiveRecord()));
  });

  bench('stampClasses', () => {
    consume(stamping.transform(sensitiveRecord()));
  });

  bench('dropClasses, record is dropped', () => {
    consume(dropping.transform(sensitiveRecord()));
  });

  bench('dropClasses, record is kept', () => {
    consume(dropping.transform(plainRecord()));
  });
});

benchFloor();
