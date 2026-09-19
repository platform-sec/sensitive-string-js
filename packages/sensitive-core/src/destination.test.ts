import { describe, expect, it } from 'vitest';
import {
  DestinationRestrictedError,
  SensitiveString,
  withRevealContext,
  wrapSensitiveByPath,
  unwrapSensitiveByPath,
} from './index.js';
import type { DestinationBinding, RevealContext } from './index.js';

const VALUE = 'DESTINATION_CANARY_9b2f';

function bound(destinations: DestinationBinding | readonly DestinationBinding[]) {
  return new SensitiveString(VALUE, 'credential', 'registry_password', { destinations });
}

/** The context the HTTP clients build for a request to `host`. */
function toward(host: string, sink = 'http'): RevealContext {
  return { name: `POST https://${host}/v2/`, tags: { sink, host } };
}

describe('destination binding', () => {
  describe('construction', () => {
    it('accepts a single binding or a list of them', () => {
      expect(() => bound({ hosts: ['registry-1.docker.io'] })).not.toThrow();
      expect(() => bound([{ hosts: ['registry-1.docker.io'] }, { sinks: ['http'] }])).not.toThrow();
    });

    it('refuses a binding that names no destination', () => {
      expect(() => bound({})).toThrow(/declares no destination/);
      expect(() => bound([])).toThrow(/empty list/);
    });

    it('refuses an empty list rather than reading it either way', () => {
      expect(() => bound({ hosts: [] })).toThrow(/empty/);
      expect(() => bound({ sinks: [] })).toThrow(/empty/);
    });

    it('refuses a host that is a URL, a path or a userinfo', () => {
      for (const entry of [
        'https://api.example.com',
        'api.example.com/v1',
        'user:pw@api.example.com',
        'api.example.com?x=1',
        'api.example.com#frag',
        'api example.com',
        '',
      ]) {
        expect(() => bound({ hosts: [entry] }), entry).toThrow(RangeError);
      }
    });

    it("refuses a wildcard anywhere but as a leading '*.'", () => {
      for (const entry of [
        '*',
        '*.',
        'api.*.com',
        'api.example.*',
        '*api.example.com',
        '*.*.com',
      ]) {
        expect(() => bound({ hosts: [entry] }), entry).toThrow(RangeError);
      }

      expect(() => bound({ hosts: ['*.example.com'] })).not.toThrow();
    });

    it('refuses a host the URL parser would spell differently', () => {
      // Each of these sits in a list matching nothing: a tag is `URL.host`,
      // which writes punycode, maps a full-width stop to a dot, and elides a
      // default port.
      for (const entry of [
        'bücher.example',
        'api.example.com\u3002',
        ':8443',
        '[',
        'api.example.com:443',
        'api.example.com:80',
        '*.example.com:443',
      ]) {
        expect(() => bound({ hosts: [entry] }), entry).toThrow(RangeError);
      }

      for (const entry of ['xn--bcher-kva.example', '[::1]:8443', '[::1]', '*.example.com:8443']) {
        expect(() => bound({ hosts: [entry] }), entry).not.toThrow();
      }
    });

    it('refuses a sink with a wildcard or whitespace', () => {
      expect(() => bound({ sinks: ['http*'] })).toThrow(RangeError);
      expect(() => bound({ sinks: ['http client'] })).toThrow(RangeError);
    });

    it('refuses a non-string entry, naming its type and not its content', () => {
      expect(() => bound({ hosts: [{ secret: VALUE } as unknown as string] })).toThrow(
        /hosts\[0\] must be a string, received object/
      );
      expect(() => bound({ sinks: 42 as unknown as string[] })).toThrow(
        /sinks must be an array of strings, received number/
      );
    });

    it('copies the lists, so mutating the caller’s array does not widen the binding', () => {
      const hosts = ['api.example.com'];
      const value = bound({ hosts });

      hosts.push('evil.example.net');

      expect(() => value.reveal(toward('evil.example.net'))).toThrow(DestinationRestrictedError);
    });
  });

  describe('the host rule', () => {
    it('matches a literal host exactly', () => {
      const value = bound({ hosts: ['registry-1.docker.io'] });

      expect(value.reveal(toward('registry-1.docker.io'))).toBe(VALUE);
      expect(() => value.reveal(toward('registry-1.docker.io.attacker.net'))).toThrow(
        DestinationRestrictedError
      );
      expect(() => value.reveal(toward('docker.io'))).toThrow(DestinationRestrictedError);
    });

    it('compares case-insensitively, since DNS names are', () => {
      const value = bound({ hosts: ['API.Example.COM'] });

      expect(value.reveal(toward('api.example.com'))).toBe(VALUE);
      expect(value.reveal(toward('Api.Example.Com'))).toBe(VALUE);
    });

    it('treats a port as part of the host, as `URL.host` does', () => {
      const withPort = bound({ hosts: ['api.example.com:8443'] });
      const withoutPort = bound({ hosts: ['api.example.com'] });

      expect(withPort.reveal(toward('api.example.com:8443'))).toBe(VALUE);
      expect(() => withPort.reveal(toward('api.example.com'))).toThrow(DestinationRestrictedError);
      expect(() => withoutPort.reveal(toward('api.example.com:8443'))).toThrow(
        DestinationRestrictedError
      );
    });

    it("matches '*.example.com' one or more labels below and not the domain itself", () => {
      const value = bound({ hosts: ['*.example.com'] });

      expect(value.reveal(toward('api.example.com'))).toBe(VALUE);
      expect(value.reveal(toward('a.b.example.com'))).toBe(VALUE);
      expect(() => value.reveal(toward('example.com'))).toThrow(DestinationRestrictedError);
      expect(() => value.reveal(toward('notexample.com'))).toThrow(DestinationRestrictedError);
      expect(() => value.reveal(toward('example.com.attacker.net'))).toThrow(
        DestinationRestrictedError
      );
    });

    it('does not normalize a trailing dot or a stated default port, and refuses instead', () => {
      const value = bound({ hosts: ['api.example.com'] });

      expect(() => value.reveal(toward('api.example.com.'))).toThrow(DestinationRestrictedError);
      expect(() => value.reveal(toward('api.example.com:443'))).toThrow(DestinationRestrictedError);
    });

    it('treats a port as part of a wildcard suffix', () => {
      const plain = bound({ hosts: ['*.example.com'] });
      const withPort = bound({ hosts: ['*.example.com:8443'] });

      expect(() => plain.reveal(toward('api.example.com:8443'))).toThrow(
        DestinationRestrictedError
      );
      expect(withPort.reveal(toward('api.example.com:8443'))).toBe(VALUE);
      expect(() => withPort.reveal(toward('api.example.com'))).toThrow(DestinationRestrictedError);
    });

    it('matches an IPv6 literal as URL.host spells it', () => {
      const value = bound({ hosts: ['[::1]:8443'] });

      expect(value.reveal(toward('[::1]:8443'))).toBe(VALUE);
      expect(() => value.reveal(toward('[::1]'))).toThrow(DestinationRestrictedError);
    });
  });

  describe('the sink rule', () => {
    it('matches a sink literally', () => {
      const value = bound({ sinks: ['anthropic'] });

      expect(value.reveal({ name: 'external:anthropic', tags: { sink: 'anthropic' } })).toBe(VALUE);
      expect(() => value.reveal({ name: 'x', tags: { sink: 'http' } })).toThrow(
        DestinationRestrictedError
      );
      expect(() => value.reveal({ name: 'x', tags: { sink: 'Anthropic' } })).toThrow(
        DestinationRestrictedError
      );
    });

    it('checks both halves when a binding names both', () => {
      const value = bound({ sinks: ['http'], hosts: ['api.example.com'] });

      expect(value.reveal(toward('api.example.com'))).toBe(VALUE);
      expect(() => value.reveal(toward('api.example.com', 'prisma'))).toThrow(
        DestinationRestrictedError
      );
      expect(() => value.reveal(toward('other.example.com'))).toThrow(DestinationRestrictedError);
    });
  });

  describe('a context that states no destination', () => {
    it('refuses with no context at all', () => {
      const value = bound({ hosts: ['api.example.com'] });

      expect(() => value.reveal()).toThrow(DestinationRestrictedError);
    });

    it('refuses under a named, reasoned context with no tags', () => {
      const value = bound({ hosts: ['api.example.com'] });

      expect(() => value.reveal({ name: 'api-call', reason: 'authenticating' })).toThrow(
        DestinationRestrictedError
      );
    });

    it('refuses the binding whose tag is missing, and says which', () => {
      const value = bound({ sinks: ['http'], hosts: ['api.example.com'] });

      let thrown: unknown;
      try {
        value.reveal({ name: 'x', tags: { sink: 'http' } });
      } catch (error) {
        thrown = error;
      }

      expect(thrown).toBeInstanceOf(DestinationRestrictedError);
      expect((thrown as DestinationRestrictedError).restriction).toBe('host');
      expect((thrown as DestinationRestrictedError).currentValue).toBeUndefined();
      expect((thrown as DestinationRestrictedError).allowedValues).toEqual(['api.example.com']);
      expect((thrown as DestinationRestrictedError).label).toBe('registry_password');
      expect(String(thrown)).toContain('states no host tag');
    });

    it('reads a tag that is not a string as absent rather than coercing it', () => {
      const value = bound({ hosts: ['api.example.com'] });

      expect(() =>
        value.reveal({ name: 'x', tags: { host: new URL('https://api.example.com/') } })
      ).toThrow(/states no host tag/);
    });

    it('reads the ambient context when the call passes none', () => {
      const value = bound({ hosts: ['api.example.com'] });

      const revealed = withRevealContext(toward('api.example.com'), () => value.reveal());
      expect(revealed).toBe(VALUE);

      withRevealContext(toward('elsewhere.example.com'), () => {
        expect(() => value.reveal()).toThrow(DestinationRestrictedError);
      });
    });
  });

  describe('the error', () => {
    it('names the tag, what the context stated, and the allowed list, and never the value', () => {
      const value = bound({ hosts: ['registry-1.docker.io'] });

      let thrown: unknown;
      try {
        value.reveal(toward('registry-1.docker.io.attacker.net'));
      } catch (error) {
        thrown = error;
      }

      const refused = thrown as DestinationRestrictedError;
      expect(refused).toBeInstanceOf(DestinationRestrictedError);
      expect(refused.code).toBe('destination-restricted');
      expect(refused.restriction).toBe('host');
      expect(refused.currentValue).toBe('registry-1.docker.io.attacker.net');
      expect(refused.allowedValues).toEqual(['registry-1.docker.io']);
      expect(refused.message).toContain("host is 'registry-1.docker.io.attacker.net'");
      expect(refused.message).not.toContain(VALUE);
    });
  });

  describe('the path helpers', () => {
    it('binds a wrapped field through the per-path options, and unwraps toward the host', () => {
      const config = {
        'registry.password': {
          klass: 'credential' as const,
          options: { destinations: { hosts: ['registry-1.docker.io'] } },
        },
      };
      const wrapped = wrapSensitiveByPath({ registry: { password: VALUE } }, config);

      expect(() => unwrapSensitiveByPath(wrapped, config)).toThrow(DestinationRestrictedError);
      expect(unwrapSensitiveByPath(wrapped, config, toward('registry-1.docker.io'))).toEqual({
        registry: { password: VALUE },
      });
    });
  });
});
