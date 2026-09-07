import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  EnvironmentLockedError,
  EnvironmentRestrictedError,
  getEnvironmentInfo,
  isEnvironmentLocked,
  lockEnvironmentInfo,
  resetEnvironmentInfo,
  SensitiveString,
  setEnvironmentInfo,
} from './index.js';
import type { EnvironmentInfo, EnvironmentRestrictions } from './index.js';

const VALUE = 'ENVIRONMENT_CANARY_4c7e';

const EU: EnvironmentInfo = { environment: 'production', region: 'eu-west-1' };
const US: EnvironmentInfo = { environment: 'production', region: 'us-east-1' };

function restricted(restrictions: EnvironmentRestrictions): SensitiveString<'sensitive'> {
  return new SensitiveString(VALUE, 'sensitive', 'eu_pii', { restrictions });
}

describe('environment restrictions', () => {
  beforeEach(() => {
    resetEnvironmentInfo();
    // Every suite here reads a restricted value, and most of them do it with an
    // environment on purpose. The undeclared-environment warning is asserted in
    // its own case; elsewhere it is noise.
    vi.spyOn(console, 'warn').mockImplementation(() => undefined);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    resetEnvironmentInfo();
  });

  describe('the environment declaration', () => {
    it('reports what was declared', () => {
      setEnvironmentInfo({
        environment: 'production',
        region: 'eu-west-1',
        datacenter: 'dc-3',
        customTags: { cluster: 'primary' },
      });

      expect(getEnvironmentInfo()).toEqual({
        environment: 'production',
        region: 'eu-west-1',
        datacenter: 'dc-3',
        customTags: { cluster: 'primary' },
      });
    });

    it('reports an unknown environment until something declares one', () => {
      expect(getEnvironmentInfo()).toEqual({ environment: 'unknown' });
    });

    it('copies what it is given, so a later mutation does not move the environment', () => {
      const tags = { cluster: 'primary' };
      const info: EnvironmentInfo = {
        environment: 'production',
        region: 'eu-west-1',
        customTags: tags,
      };

      setEnvironmentInfo(info);

      info.region = 'us-east-1';
      tags.cluster = 'secondary';

      expect(getEnvironmentInfo().region).toBe('eu-west-1');
      expect(getEnvironmentInfo().customTags).toEqual({ cluster: 'primary' });
    });

    it('hands back a frozen object, so a reader cannot write to it either', () => {
      setEnvironmentInfo({ environment: 'production', customTags: { cluster: 'primary' } });

      const info = getEnvironmentInfo();

      expect(Object.isFrozen(info)).toBe(true);
      expect(Object.isFrozen(info.customTags)).toBe(true);
    });

    it('refuses a declaration it cannot use', () => {
      expect(() => setEnvironmentInfo(undefined as unknown as EnvironmentInfo)).toThrow(TypeError);
      expect(() => setEnvironmentInfo({ environment: 7 as unknown as string })).toThrow(TypeError);
      expect(() => setEnvironmentInfo({ environment: '' })).toThrow(RangeError);
      expect(() => setEnvironmentInfo({ environment: 'p', region: '' })).toThrow(RangeError);
      expect(() =>
        setEnvironmentInfo({
          environment: 'p',
          customTags: { a: 1 } as unknown as Record<string, string>,
        })
      ).toThrow(TypeError);
      expect(() =>
        setEnvironmentInfo({
          environment: 'p',
          customTags: [] as unknown as Record<string, string>,
        })
      ).toThrow(TypeError);
    });

    it('is reachable under the Symbol.for key a second copy of core would use', () => {
      setEnvironmentInfo({ environment: 'production', region: 'eu-west-1' });

      const key = Symbol.for('@platform-sec/sensitive-string-core/environment');
      const shared = (globalThis as unknown as Record<symbol, { info: EnvironmentInfo }>)[key];

      // A second physical installation calls getGlobalSingleton with this same
      // key and receives this same object, so an application that resolves two
      // copies of core declares one environment rather than two.
      expect(shared?.info.region).toBe('eu-west-1');
    });
  });

  describe('the lock', () => {
    it('refuses a later declaration', () => {
      setEnvironmentInfo(EU);
      lockEnvironmentInfo();

      expect(isEnvironmentLocked()).toBe(true);
      expect(() => setEnvironmentInfo(US)).toThrow(EnvironmentLockedError);
      expect(getEnvironmentInfo().region).toBe('eu-west-1');
    });

    it('keeps a restricted value refusing after an attempt to move the environment', () => {
      setEnvironmentInfo(US);
      lockEnvironmentInfo();

      const value = restricted({ allowedRegions: ['eu-*'] });

      expect(() => setEnvironmentInfo(EU)).toThrow(EnvironmentLockedError);
      expect(() => value.reveal()).toThrow(EnvironmentRestrictedError);
    });

    it('is cleared by the reset that exists for test isolation', () => {
      lockEnvironmentInfo();
      resetEnvironmentInfo();

      expect(isEnvironmentLocked()).toBe(false);
      expect(() => setEnvironmentInfo(EU)).not.toThrow();
    });
  });

  describe('environment matching', () => {
    it('permits a reveal in an allowed environment', () => {
      setEnvironmentInfo({ environment: 'production' });

      expect(restricted({ allowedEnvironments: ['production'] }).reveal()).toBe(VALUE);
    });

    it('permits a reveal in any of several allowed environments', () => {
      setEnvironmentInfo({ environment: 'staging' });

      expect(restricted({ allowedEnvironments: ['production', 'staging'] }).reveal()).toBe(VALUE);
    });

    it('refuses a reveal outside the allowlist', () => {
      setEnvironmentInfo({ environment: 'development' });

      expect(() => restricted({ allowedEnvironments: ['production'] }).reveal()).toThrow(
        EnvironmentRestrictedError
      );
    });

    it('refuses a reveal in a denied environment', () => {
      setEnvironmentInfo({ environment: 'development' });

      expect(() => restricted({ deniedEnvironments: ['development', 'test'] }).reveal()).toThrow(
        EnvironmentRestrictedError
      );
    });

    it('permits a reveal outside the denylist', () => {
      setEnvironmentInfo({ environment: 'production' });

      expect(restricted({ deniedEnvironments: ['development', 'test'] }).reveal()).toBe(VALUE);
    });

    it('denies a name that is on both lists', () => {
      setEnvironmentInfo({ environment: 'staging' });

      const value = restricted({
        allowedEnvironments: ['staging'],
        deniedEnvironments: ['staging'],
      });

      // Both lists apply, so the denylist is what decides. A value that names
      // the same environment twice is a configuration mistake, and refusing is
      // the direction to be wrong in.
      expect(() => value.reveal()).toThrow(EnvironmentRestrictedError);
    });

    it('compares literally, without folding case', () => {
      setEnvironmentInfo({ environment: 'Production' });

      expect(() => restricted({ allowedEnvironments: ['production'] }).reveal()).toThrow(
        EnvironmentRestrictedError
      );
    });
  });

  describe('region matching', () => {
    it('permits a reveal in an allowed region', () => {
      setEnvironmentInfo(EU);

      expect(restricted({ allowedRegions: ['eu-west-1', 'eu-central-1'] }).reveal()).toBe(VALUE);
    });

    it('refuses a reveal outside the allowlist', () => {
      setEnvironmentInfo(US);

      expect(() => restricted({ allowedRegions: ['eu-west-1'] }).reveal()).toThrow(
        EnvironmentRestrictedError
      );
    });

    it('matches a trailing wildcard as a prefix', () => {
      setEnvironmentInfo({ environment: 'production', region: 'eu-north-1' });

      expect(restricted({ allowedRegions: ['eu-*'] }).reveal()).toBe(VALUE);

      setEnvironmentInfo({ environment: 'production', region: 'us-east-1' });
      resetEnvironmentInfo();
      setEnvironmentInfo(US);

      expect(() => restricted({ allowedRegions: ['eu-*'] }).reveal()).toThrow(
        EnvironmentRestrictedError
      );
    });

    it('refuses a reveal in a denied region, wildcard included', () => {
      setEnvironmentInfo({ environment: 'production', region: 'cn-north-1' });

      expect(() => restricted({ deniedRegions: ['cn-*', 'ru-*'] }).reveal()).toThrow(
        EnvironmentRestrictedError
      );
    });

    it('permits a reveal outside every denied pattern', () => {
      setEnvironmentInfo(EU);

      expect(restricted({ deniedRegions: ['cn-*', 'ru-*'] }).reveal()).toBe(VALUE);
    });

    it("treats a bare '*' as every region", () => {
      setEnvironmentInfo(US);

      expect(restricted({ allowedRegions: ['*'] }).reveal()).toBe(VALUE);
      expect(() => restricted({ deniedRegions: ['*'] }).reveal()).toThrow(
        EnvironmentRestrictedError
      );
    });
  });

  describe('an environment that does not state a field', () => {
    it('refuses an allowlist, because "only here" is not satisfied by not knowing where', () => {
      setEnvironmentInfo({ environment: 'production' });

      const error = captureError(() => restricted({ allowedRegions: ['eu-*'] }).reveal());

      expect(error).toBeInstanceOf(EnvironmentRestrictedError);
      expect((error as EnvironmentRestrictedError).currentValue).toBeUndefined();
      expect(String(error)).toContain('states no region');
    });

    it('passes a denylist, because "not there" concludes nothing from silence', () => {
      setEnvironmentInfo({ environment: 'production' });

      expect(restricted({ deniedRegions: ['cn-*'] }).reveal()).toBe(VALUE);
    });

    it('applies the same rule to a datacenter', () => {
      setEnvironmentInfo({ environment: 'production' });

      expect(() => restricted({ allowedDatacenters: ['dc-1'] }).reveal()).toThrow(
        EnvironmentRestrictedError
      );
      expect(restricted({ deniedDatacenters: ['dc-9'] }).reveal()).toBe(VALUE);
    });

    it('warns once that nothing declared an environment', () => {
      const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);

      expect(restricted({ deniedRegions: ['cn-*'] }).reveal()).toBe(VALUE);
      expect(restricted({ deniedRegions: ['cn-*'] }).reveal()).toBe(VALUE);

      expect(warn).toHaveBeenCalledTimes(1);
      expect(warn.mock.calls[0]?.[0]).toContain('setEnvironmentInfo');
    });

    it('says nothing once an environment has been declared', () => {
      const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
      setEnvironmentInfo(EU);

      expect(restricted({ allowedRegions: ['eu-*'] }).reveal()).toBe(VALUE);
      expect(warn).not.toHaveBeenCalled();
    });
  });

  describe('datacenter matching', () => {
    it('permits a reveal in an allowed datacenter and refuses elsewhere', () => {
      setEnvironmentInfo({ environment: 'production', datacenter: 'dc-1' });

      expect(restricted({ allowedDatacenters: ['dc-1', 'dc-2'] }).reveal()).toBe(VALUE);
      expect(() => restricted({ allowedDatacenters: ['dc-2'] }).reveal()).toThrow(
        EnvironmentRestrictedError
      );
    });

    it('matches literally, so a wildcard is refused at construction', () => {
      expect(() => restricted({ allowedDatacenters: ['dc-*'] })).toThrow(RangeError);
    });
  });

  describe('custom restrictions', () => {
    it('permits a reveal when the function answers true', () => {
      setEnvironmentInfo({ environment: 'production', customTags: { cluster: 'primary' } });

      const value = restricted({ custom: (env) => env.customTags?.['cluster'] === 'primary' });

      expect(value.reveal()).toBe(VALUE);
    });

    it('refuses when the function answers false', () => {
      setEnvironmentInfo({ environment: 'production', customTags: { cluster: 'secondary' } });

      const value = restricted({ custom: (env) => env.customTags?.['cluster'] === 'primary' });

      expect(() => value.reveal()).toThrow(EnvironmentRestrictedError);
    });

    it('hands the function the whole environment, frozen', () => {
      setEnvironmentInfo({
        environment: 'staging',
        region: 'eu-west-1',
        datacenter: 'dc-3',
        customTags: { cluster: 'primary' },
      });

      const seen: EnvironmentInfo[] = [];
      const value = restricted({
        custom: (env) => {
          seen.push(env);
          return true;
        },
      });

      value.reveal();

      expect(seen).toHaveLength(1);
      expect(seen[0]).toEqual({
        environment: 'staging',
        region: 'eu-west-1',
        datacenter: 'dc-3',
        customTags: { cluster: 'primary' },
      });
      expect(Object.isFrozen(seen[0])).toBe(true);
    });

    it('refuses when the function throws, and keeps what it threw as the cause', () => {
      setEnvironmentInfo(EU);

      const boom = new Error('metadata service unreachable');
      const value = restricted({
        custom: () => {
          throw boom;
        },
      });

      const error = captureError(() => value.reveal());

      expect(error).toBeInstanceOf(EnvironmentRestrictedError);
      expect((error as EnvironmentRestrictedError).cause).toBe(boom);
      expect(String(error)).toContain('threw instead of answering');
    });

    it('refuses an answer that is not a boolean, an async function included', () => {
      setEnvironmentInfo(EU);

      // An async function returns a Promise, which is truthy: read as an
      // answer it would allow every read the function was written to refuse.
      const asyncCustom = restricted({
        custom: (() => Promise.resolve(false)) as unknown as (env: EnvironmentInfo) => boolean,
      });
      const truthy = restricted({
        custom: (() => 'yes') as unknown as (env: EnvironmentInfo) => boolean,
      });

      expect(() => asyncCustom.reveal()).toThrow(EnvironmentRestrictedError);
      expect(() => truthy.reveal()).toThrow(EnvironmentRestrictedError);
      expect(String(captureError(() => truthy.reveal()))).toContain('instead of a boolean');
    });

    it('reports the caller message when there is one', () => {
      setEnvironmentInfo(EU);

      const value = restricted({
        custom: () => false,
        customMessage: 'only the primary cluster may read this',
      });

      expect(String(captureError(() => value.reveal()))).toContain(
        'only the primary cluster may read this'
      );
    });

    it('is asked after the declarative lists, so the concrete refusal wins', () => {
      setEnvironmentInfo(US);
      let asked = false;

      const value = restricted({
        allowedRegions: ['eu-*'],
        custom: () => {
          asked = true;
          return true;
        },
      });

      expect((captureError(() => value.reveal()) as EnvironmentRestrictedError).restriction).toBe(
        'region'
      );
      expect(asked).toBe(false);
    });
  });

  describe('what the constructor refuses', () => {
    it('refuses an empty list rather than guessing which way to read it', () => {
      expect(() => restricted({ allowedRegions: [] })).toThrow(RangeError);
      expect(() => restricted({ deniedEnvironments: [] })).toThrow(RangeError);
      expect(() => new SensitiveString(VALUE, 'sensitive', 'x', { restrictions: [] })).toThrow(
        RangeError
      );
    });

    it('refuses a restriction set that restricts nothing', () => {
      expect(() => restricted({})).toThrow(Error);
      expect(() => restricted({ customMessage: 'no function to describe' })).toThrow(Error);
    });

    it('refuses a wildcard anywhere but at the end of a region pattern', () => {
      expect(() => restricted({ allowedRegions: ['*-east-1'] })).toThrow(RangeError);
      expect(() => restricted({ deniedRegions: ['eu-*-1'] })).toThrow(RangeError);
      expect(() => restricted({ allowedRegions: ['eu-*', '*-west-2'] })).toThrow(RangeError);
    });

    it('refuses a wildcard in a field that is matched literally', () => {
      expect(() => restricted({ allowedEnvironments: ['prod*'] })).toThrow(RangeError);
      expect(() => restricted({ deniedDatacenters: ['dc-*'] })).toThrow(RangeError);
    });

    it('refuses entries and options it cannot use', () => {
      expect(() => restricted({ allowedRegions: 'eu-*' as unknown as string[] })).toThrow(
        TypeError
      );
      expect(() => restricted({ allowedRegions: [7] as unknown as string[] })).toThrow(TypeError);
      expect(() => restricted({ allowedRegions: [''] })).toThrow(RangeError);
      expect(() => restricted({ custom: 'yes' as unknown as () => boolean })).toThrow(TypeError);
      expect(() =>
        restricted({ custom: () => true, customMessage: 7 as unknown as string })
      ).toThrow(TypeError);
      expect(
        () =>
          new SensitiveString(VALUE, 'sensitive', 'x', {
            restrictions: [null] as unknown as EnvironmentRestrictions[],
          })
      ).toThrow(TypeError);
    });

    it('copies the caller list, so mutating it afterwards does not widen the restriction', () => {
      setEnvironmentInfo(US);

      const allowedRegions = ['eu-west-1'];
      const value = restricted({ allowedRegions });

      allowedRegions.push('us-east-1');

      expect(() => value.reveal()).toThrow(EnvironmentRestrictedError);
    });
  });

  describe('the error', () => {
    it('names the restriction, the current value and the allowed values', () => {
      setEnvironmentInfo(US);

      const error = captureError(() =>
        restricted({ allowedRegions: ['eu-west-1', 'eu-central-1'] }).reveal()
      ) as EnvironmentRestrictedError;

      expect(error.restriction).toBe('region');
      expect(error.currentValue).toBe('us-east-1');
      expect(error.allowedValues).toEqual(['eu-west-1', 'eu-central-1']);
      expect(error.deniedValues).toBeUndefined();
      expect(error.label).toBe('eu_pii');
      expect(error.message).toContain("'eu_pii'");
      expect(error.message).toContain('us-east-1');
      expect(error.message).toContain('eu-west-1, eu-central-1');
    });

    it('names the denied values when a denylist is what refused', () => {
      setEnvironmentInfo({ environment: 'development' });

      const error = captureError(() =>
        restricted({ deniedEnvironments: ['development', 'test'] }).reveal()
      ) as EnvironmentRestrictedError;

      expect(error.restriction).toBe('environment');
      expect(error.currentValue).toBe('development');
      expect(error.allowedValues).toBeUndefined();
      expect(error.deniedValues).toEqual(['development', 'test']);
    });

    it('works on a value with no label', () => {
      setEnvironmentInfo(US);

      const value = new SensitiveString(VALUE, 'sensitive', undefined, {
        restrictions: { allowedRegions: ['eu-*'] },
      });
      const error = captureError(() => value.reveal()) as EnvironmentRestrictedError;

      expect(error.label).toBeUndefined();
      expect(error.message).toContain('Sensitive value cannot be read');
    });
  });
});

/** Run `fn` and hand back whatever it threw, or fail if it threw nothing. */
function captureError(fn: () => unknown): unknown {
  try {
    fn();
  } catch (error) {
    return error;
  }

  expect.unreachable('expected the operation to be refused');
}
