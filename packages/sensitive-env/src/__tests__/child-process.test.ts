import { execFileSync } from 'node:child_process';

import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { describe, it, expect } from 'vitest';

import { toChildEnv } from '../child.js';
import { loadEnv } from '../load.js';
import { ChildEnvRefusedError } from '../types.js';

/**
 * The marker test, run against a real child process.
 *
 * The unit suite asserts the guard refuses. This asserts the two things a unit
 * test cannot: that a `SensitiveString` reaching a spawn environment really does
 * arrive at the child as the literal marker text, and that `toChildEnv`'s
 * output really does arrive as the credential.
 */

const CANARY = 'LEAKED_SECRET_abc123xyz';
const CTX = { name: 'child-process-test', reason: 'verify the boundary' };

/** A child that prints one variable back. */
function readBack(env: NodeJS.ProcessEnv): string {
  return execFileSync(process.execPath, ['-e', 'process.stdout.write(process.env.PROBE ?? "")'], {
    env,
    encoding: 'utf8',
  });
}

describe('the environment boundary', () => {
  it('coerces an instance to its marker on the way to a child', () => {
    const wrapped = new SensitiveString(CANARY, 'credential', 'probe');

    const received = readBack({ PROBE: wrapped as unknown as string });

    // This is the failure the guard exists for. Nothing threw, the child
    // started, and it authenticated with the literal text.
    expect(received).toBe('[REDACTED:credential]');
    expect(received).not.toContain(CANARY);
  });

  it('hands a child the revealed value through toChildEnv', () => {
    const record = loadEnv(
      { fields: { PROBE: 'credential' }, fallback: 'plain' },
      { source: { PROBE: CANARY } }
    );

    const received = readBack(toChildEnv(record, ['PROBE'], CTX));

    expect(received).toBe(CANARY);
  });

  it('refuses before a spawn is reached, so a fake spawn records no call', () => {
    const calls: unknown[] = [];
    const fakeSpawn = (env: Record<string, string>): void => {
      calls.push(env);
    };

    const record = loadEnv(
      { fallback: 'plain' },
      // eslint-disable-next-line @typescript-eslint/restrict-template-expressions -- the coercion is the subject
      { source: { PROBE: `${new SensitiveString(CANARY, 'credential')}` } }
    );

    expect(() => fakeSpawn(toChildEnv(record, ['PROBE'], CTX))).toThrow(ChildEnvRefusedError);
    expect(calls).toEqual([]);
  });

  it('refuses a mixed object before any of it reaches a child', () => {
    const record = loadEnv(
      { fields: { GOOD: 'credential' }, fallback: 'plain' },
      { source: { GOOD: CANARY, PROBE: '[REDACTED:credential]' } }
    );

    let built: Record<string, string> | undefined;
    try {
      built = toChildEnv(record, ['GOOD', 'PROBE'], CTX);
    } catch (error) {
      expect((error as ChildEnvRefusedError).reason).toBe('marker');
    }

    expect(built).toBeUndefined();
  });

  it('does not export anything the caller did not ask for', () => {
    const record = loadEnv(
      { fields: { OTHER: 'credential' }, fallback: 'plain' },
      { source: { PROBE: 'asked-for', OTHER: CANARY } }
    );

    const childEnv = toChildEnv(record, ['PROBE'], CTX);

    expect(readBack(childEnv)).toBe('asked-for');
    expect(JSON.stringify(childEnv)).not.toContain(CANARY);
  });
});
