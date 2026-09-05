import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import {
  COLLECTED_REQUEST_HEADERS,
  HEADER_ATTR_NAMES,
  camelCaseHeader,
  headerAttributeName,
  headerSpellings,
} from '../names.js';
import { AGENT_VERSION, agentRequire } from './fixtures.js';

/**
 * The reproduction, pinned against the shipped agent.
 *
 * `names.ts` carries a copy of `HEADER_ATTR_NAMES` and `_headerToCamelCase`
 * rather than importing them, because importing a private module of the agent
 * to compute a security-critical list makes the package break on a refactor
 * that would otherwise be invisible. This file is what keeps the copy honest:
 * it reaches into the same private module the copy was taken from and requires
 * the two to agree, so a vendor change fails here rather than going unnoticed
 * in a generated configuration.
 *
 * Measured against `newrelic` 14.3.10 on Node 22.15.0.
 */

const require_ = agentRequire();

/** The agent's own map, read off the module the reproduction was taken from. */
function shippedHeaderAttributes(): Record<string, string> {
  const path = require_.resolve('newrelic/lib/header-attributes.js');
  const source = readFileSync(path, 'utf8');
  const block = /const HEADER_ATTR_NAMES = \{([\s\S]*?)\n\}/.exec(source);

  if (block?.[1] === undefined) {
    throw new Error(
      `HEADER_ATTR_NAMES was not found in ${path}. The agent has moved or renamed it, ` +
        'and the reproduction in names.ts must be re-taken by hand.'
    );
  }

  const map: Record<string, string> = {};

  for (const line of block[1].split('\n')) {
    const entry = /^\s*'?([A-Za-z0-9-]+)'?\s*:\s*'([A-Za-z0-9]+)'/.exec(line);

    if (entry?.[1] !== undefined && entry[2] !== undefined) {
      map[entry[1]] = entry[2];
    }
  }

  return map;
}

/**
 * The agent's own `_collectHeaders`, exercised through the only door it has.
 *
 * `_headerToCamelCase` is not exported, so the fallback is checked through
 * `collectRequestHeaders` against a stub transaction that records what the
 * agent asked to write.
 */
function shippedAttributeName(header: string): string {
  const { collectRequestHeaders } = require_('newrelic/lib/header-attributes.js') as {
    collectRequestHeaders: (headers: Record<string, string>, transaction: unknown) => void;
  };

  const written: string[] = [];
  const transaction = {
    agent: {
      config: { allow_all_headers: true },
      tracer: { getSegment: () => ({ addSpanAttribute: () => undefined }) },
    },
    trace: {
      attributes: {
        addAttribute: (_destination: number, name: string) => {
          written.push(name);
        },
      },
    },
  };

  collectRequestHeaders({ [header]: 'value' }, transaction);

  const name = written[0];

  if (name === undefined) {
    throw new Error(`the agent wrote no attribute for the header '${header}'`);
  }

  return name;
}

describe(`HEADER_ATTR_NAMES against newrelic ${AGENT_VERSION}`, () => {
  const shipped = shippedHeaderAttributes();

  it('reads the agent map at all, so a silent empty comparison cannot pass', () => {
    expect(Object.keys(shipped).length).toBe(50);
  });

  it('reproduces every entry the agent ships', () => {
    expect({ ...HEADER_ATTR_NAMES }).toEqual(shipped);
  });

  it('names no header the agent does not', () => {
    const extra = Object.keys(HEADER_ATTR_NAMES).filter((key) => !(key in shipped));

    expect(extra).toEqual([]);
  });

  it.each(Object.keys(HEADER_ATTR_NAMES))(
    'agrees with the agent on the attribute name for %s',
    (header) => {
      expect(headerAttributeName(header, 'request.headers.')).toBe(shippedAttributeName(header));
    }
  );
});

describe('camelCaseHeader against the agent fallback', () => {
  /**
   * Shapes outside the map, where the fallback decides.
   *
   * Each of these is a way a hand-written exclusion goes wrong, and the last
   * two are the reason `headerSpellings` emits more than one rule: only the
   * first character is lowercased, so two spellings of one header produce two
   * different attributes.
   */
  const FIXTURES = [
    'x-api-key',
    'x-internal-signature',
    'x_underscored_name',
    'single',
    'a',
    'X',
    'X-Api-Key',
    'X-API-KEY',
    'x--double--hyphen',
    'trailing-',
    '-leading',
  ];

  it.each(FIXTURES)('agrees with the agent on %s', (header) => {
    expect(headerAttributeName(header, 'request.headers.')).toBe(shippedAttributeName(header));
  });

  it('lowercases a single character and returns it', () => {
    expect(camelCaseHeader('A')).toBe('a');
  });

  it('returns the empty string for an empty name', () => {
    expect(camelCaseHeader('')).toBe('');
  });

  it('lowercases only the first character, so casing is not normalized away', () => {
    expect(camelCaseHeader('x-api-key')).toBe('xApiKey');
    expect(camelCaseHeader('X-API-KEY')).toBe('xAPIKEY');
  });
});

describe('headerSpellings', () => {
  it('covers both the casing the agent maps and the one it derives', () => {
    const spellings = headerSpellings('X-API-KEY', 'request.headers.');

    expect(spellings).toContain('request.headers.xApiKey');
    expect(spellings).toContain('request.headers.xAPIKEY');
  });

  it('keeps the raw name, which is what a reader of the configuration expects', () => {
    expect(headerSpellings('x-api-key', 'request.headers.')).toContain('request.headers.x-api-key');
  });

  it('deduplicates a name whose spellings all agree', () => {
    expect(headerSpellings('authorization', 'request.headers.')).toEqual([
      'request.headers.authorization',
    ]);
  });
});

describe('COLLECTED_REQUEST_HEADERS', () => {
  it('reproduces the six the agent collects with allow_all_headers off', () => {
    const source = readFileSync(require_.resolve('newrelic/lib/header-attributes.js'), 'utf8');
    const block = /const COLLECTED_REQUEST_HEADERS = \[([\s\S]*?)\]/.exec(source);
    const shipped = [...(block?.[1] ?? '').matchAll(/'([a-z-]+)'/g)].map((match) => match[1]);

    expect(shipped.length).toBe(6);
    expect([...COLLECTED_REQUEST_HEADERS]).toEqual(shipped);
  });

  it('carries no credential, which is why stock defaults do not leak', () => {
    expect(COLLECTED_REQUEST_HEADERS).not.toContain('authorization');
    expect(COLLECTED_REQUEST_HEADERS).not.toContain('cookie');
  });
});
