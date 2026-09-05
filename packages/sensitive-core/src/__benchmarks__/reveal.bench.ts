/**
 * Reveal, and the context machinery around it.
 *
 * Two costs are separated here. The first group prices a reveal itself,
 * against reading a plain field, and prices what an audit hook adds. The
 * second prices `withRevealContext`, which enters an AsyncLocalStorage scope:
 * that cost is paid once per scope rather than once per reveal, so a run that
 * shows it as expensive relative to a reveal is not by itself an argument
 * against using it.
 */

import { bench, describe } from 'vitest';

import { SensitiveString } from '../sensitive-string.js';
import {
  createChildContext,
  getCurrentRevealContext,
  withAuditedReveals,
  withRevealContext,
} from '../context.js';
import type { RevealContext } from '../types.js';
import { benchFloor, consume, TOKEN } from './fixtures.js';

const credential = new SensitiveString(TOKEN, 'credential', 'access_token');
const holder = { value: TOKEN };

/** A context with no hook, so entering the scope is all that is measured. */
const BARE: RevealContext = { name: 'bench', reason: 'benchmark' };

/** Counted rather than logged, so the hook does real work without doing I/O. */
let audited = 0;
const AUDITING: RevealContext = {
  name: 'bench-audited',
  reason: 'benchmark',
  auditReveal: () => {
    audited += 1;
  },
};

describe('reveal', () => {
  bench('plain field read (control)', () => {
    consume(holder.value);
  });

  bench('no context', () => {
    consume(credential.reveal());
  });

  bench('inline context', () => {
    consume(credential.reveal(BARE));
  });

  bench('inline context with audit hook', () => {
    consume(credential.reveal(AUDITING));
  });
});

describe('reveal under an ambient context', () => {
  bench('outside any context', () => {
    consume(credential.reveal());
  });

  bench('inside a bare context', () => {
    withRevealContext(BARE, () => {
      consume(credential.reveal());
    });
  });

  bench('inside an auditing context', () => {
    withRevealContext(AUDITING, () => {
      consume(credential.reveal());
    });
  });

  bench('ten reveals inside one context', () => {
    withRevealContext(BARE, () => {
      for (let index = 0; index < 10; index += 1) {
        consume(credential.reveal());
      }
    });
  });
});

describe('context scope', () => {
  bench('bare closure (control)', () => {
    consume(((): number => 1)());
  });

  bench('withRevealContext', () => {
    withRevealContext(BARE, () => {
      consume(1);
    });
  });

  bench('withRevealContext, nested twice', () => {
    withRevealContext(BARE, () => {
      withRevealContext(AUDITING, () => {
        consume(1);
      });
    });
  });

  bench('withAuditedReveals', () => {
    withAuditedReveals(
      'bench',
      () => {
        audited += 1;
      },
      () => {
        consume(1);
      }
    );
  });
});

describe('context lookup', () => {
  bench('getCurrentRevealContext, none set', () => {
    consume(getCurrentRevealContext());
  });

  bench('getCurrentRevealContext, one set', () => {
    withRevealContext(BARE, () => {
      consume(getCurrentRevealContext());
    });
  });

  bench('createChildContext', () => {
    withRevealContext(BARE, () => {
      consume(createChildContext({ name: 'child' }));
    });
  });
});

describe('reveal audit count', () => {
  // The counter is read so the hook above cannot be optimized to nothing.
  bench('report', () => {
    consume(audited);
  });
});

benchFloor();
