import { afterEach, describe, expect, it, vi } from 'vitest';
import { DestinationRestrictedError, SensitiveString } from '@platform-sec/sensitive-string-core';
import axios from 'axios';

import { createSensitiveAxios } from './client.js';
import { resolveProxyHost } from './proxy.js';

const CANARY = 'PROXY_CANARY_7e2a';
const target = new URL('https://api.example.com/v1/');

describe('resolveProxyHost', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('reads config.proxy as host:port, and false as no proxy', () => {
    expect(resolveProxyHost(target, { proxy: { host: 'Proxy.corp.example', port: 3128 } })).toBe(
      'proxy.corp.example:3128'
    );
    vi.stubEnv('HTTPS_PROXY', 'http://env.corp.example:8080');
    expect(resolveProxyHost(target, { proxy: false })).toBeUndefined();
  });

  it('reads the environment the way proxy-from-env does', () => {
    vi.stubEnv('https_proxy', 'http://env.corp.example:8080');
    expect(resolveProxyHost(target, {})).toBe('env.corp.example:8080');

    // The other scheme's variable does not apply.
    vi.unstubAllEnvs();
    vi.stubEnv('HTTP_PROXY', 'http://env.corp.example:8080');
    expect(resolveProxyHost(target, {})).toBeUndefined();
    expect(resolveProxyHost(new URL('http://api.example.com/'), {})).toBe('env.corp.example:8080');

    vi.unstubAllEnvs();
    vi.stubEnv('ALL_PROXY', 'all.corp.example:9');
    expect(resolveProxyHost(target, {})).toBe('all.corp.example:9');
  });

  it('honours no_proxy in its four spellings', () => {
    vi.stubEnv('HTTPS_PROXY', 'http://env.corp.example:8080');

    vi.stubEnv('NO_PROXY', '*');
    expect(resolveProxyHost(target, {})).toBeUndefined();

    vi.stubEnv('NO_PROXY', 'api.example.com');
    expect(resolveProxyHost(target, {})).toBeUndefined();

    vi.stubEnv('NO_PROXY', '.example.com');
    expect(resolveProxyHost(target, {})).toBeUndefined();

    vi.stubEnv('NO_PROXY', '*.example.com');
    expect(resolveProxyHost(target, {})).toBeUndefined();

    // A port that does not match leaves the proxy in force.
    vi.stubEnv('NO_PROXY', 'api.example.com:8443');
    expect(resolveProxyHost(target, {})).toBe('env.corp.example:8080');

    vi.stubEnv('NO_PROXY', 'other.example.net, more.example.org');
    expect(resolveProxyHost(target, {})).toBe('env.corp.example:8080');
  });

  it('reads a proxy agent that exposes its proxy, and nothing from an opaque agent', () => {
    expect(
      resolveProxyHost(target, {
        httpsAgent: { proxy: new URL('http://agent.corp.example:3128/') },
      })
    ).toBe('agent.corp.example:3128');
    expect(resolveProxyHost(target, { httpsAgent: { proxy: 'agent.corp.example:3128' } })).toBe(
      'agent.corp.example:3128'
    );
    // The http agent does not apply to an https URL.
    expect(
      resolveProxyHost(target, { httpAgent: { proxy: new URL('http://agent.corp.example:3128/') } })
    ).toBeUndefined();
    expect(resolveProxyHost(target, { httpsAgent: { keepAlive: true } })).toBeUndefined();
  });
});

describe('a host-bound value through the client', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('refuses before sending when a proxy the binding does not name would receive the bytes', async () => {
    vi.stubEnv('HTTPS_PROXY', 'http://env.corp.example:8080');
    const bound = new SensitiveString(CANARY, 'credential', 'registry', {
      destinations: { hosts: ['api.example.com'] },
    });
    const client = createSensitiveAxios(axios.create());

    // Refused by the gate ahead of any socket: the URL is not reachable and
    // the rejection is the binding's, not a network error.
    await expect(
      client.get('https://api.example.com/v1/', { headers: { 'x-api-key': bound } })
    ).rejects.toBeInstanceOf(DestinationRestrictedError);

    await expect(
      client.get('https://api.example.com/v1/', {
        headers: { 'x-api-key': bound },
        proxy: { host: 'other.corp.example', port: 3128 },
      })
    ).rejects.toBeInstanceOf(DestinationRestrictedError);
  });
});
