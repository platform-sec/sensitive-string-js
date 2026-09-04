/**
 * The wire format.
 *
 * `serialize()` is a reveal that produces a plain object, and `deserialize()`
 * validates one back into an instance. Both run per value per hop, so a
 * service that forwards a payload of secrets pays them in proportion to how
 * many fields it carries rather than how large they are.
 *
 * `deserialize` is the one to watch: it is the boundary that has to reject a
 * hostile payload, so it does more work than the symmetry with `serialize`
 * suggests.
 */

import { bench, describe } from 'vitest';

import { SensitiveString } from '../sensitive-string.js';
import { carriesSerializedMarker, redactSerialized, serializedClass } from '../serialized.js';
import { redactInStructure } from '../redact.js';
import { consume, consumeFlag, LENGTHS, TOKEN, valueOfLength } from './fixtures.js';

const credential = new SensitiveString(TOKEN, 'credential', 'access_token');
const expiring = new SensitiveString(TOKEN, 'credential', 'access_token', { ttl: 3_600_000 });

const wire = credential.serialize();
const wireWithDeadline = expiring.serialize();

/** A payload of serialized values, the shape a forwarding service holds. */
const wirePayload = {
  requestId: 'req-0f8c2a1b',
  auth: { token: wire, refresh: wireWithDeadline },
};

describe('serialize', () => {
  bench('reveal only (control)', () => {
    consume(credential.reveal());
  });

  bench('serialize', () => {
    consume(credential.serialize());
  });

  bench('serialize, carries a deadline', () => {
    consume(expiring.serialize());
  });

  bench('serialize then JSON.stringify', () => {
    consume(JSON.stringify(credential.serialize()));
  });
});

describe('deserialize', () => {
  bench('construction from the raw value (control)', () => {
    consume(new SensitiveString(TOKEN, 'credential', 'access_token'));
  });

  bench('deserialize', () => {
    consume(SensitiveString.deserialize(wire));
  });

  bench('deserialize, carries a deadline', () => {
    consume(SensitiveString.deserialize(wireWithDeadline));
  });
});

describe('round trip', () => {
  bench('serialize then deserialize', () => {
    consume(SensitiveString.deserialize(credential.serialize()));
  });

  bench('through JSON', () => {
    consume(SensitiveString.deserialize(JSON.parse(JSON.stringify(credential.serialize()))));
  });
});

describe('round trip by value length', () => {
  for (const length of LENGTHS) {
    const instance = new SensitiveString(valueOfLength(length), 'credential');

    bench(`${length} chars`, () => {
      consume(SensitiveString.deserialize(instance.serialize()));
    });
  }
});

describe('recognizing a serialized value', () => {
  bench('carriesSerializedMarker', () => {
    consumeFlag(carriesSerializedMarker(wire));
  });

  bench('serializedClass', () => {
    consume(serializedClass(wire));
  });

  bench('redactSerialized', () => {
    consume(redactSerialized(wire));
  });

  bench('redactInStructure over a wire payload', () => {
    consume(redactInStructure(wirePayload));
  });
});
