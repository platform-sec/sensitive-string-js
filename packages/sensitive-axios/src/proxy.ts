import type { AxiosProxyConfig } from 'axios';

/** The three axios options this reads, typed as axios declares them. */
export interface ProxyRelevantConfig {
  readonly proxy?: AxiosProxyConfig | false | undefined;
  readonly httpAgent?: unknown;
  readonly httpsAgent?: unknown;
}

/**
 * The proxy axios will send a request through, as `host[:port]`, or
 * `undefined` for a direct request.
 *
 * axios decides this in its http adapter: `config.proxy` when it is an
 * object, none when it is `false`, and otherwise whatever `proxy-from-env`
 * reads out of `<scheme>_proxy` or `all_proxy`, subject to `no_proxy`. The
 * rules below are that library's, `proxy-from-env` 2.1.0, restated rather
 * than imported: it is axios's own dependency, not this package's, and a
 * transitive import is a resolution that works on one install layout and not
 * another.
 *
 * The corpus record this answers is the one where a proxy setting changed
 * the machine that received a credential and left the URL untouched, so the
 * wrapper's host check passed. What this returns is tagged on the reveal
 * context as `proxy`, and a host-bound value refuses when it is not a host
 * the binding names.
 *
 * Two shapes are read beyond axios's own option. An agent on `httpAgent` or
 * `httpsAgent` that exposes a `proxy` property as a `URL` or a string, which
 * is what `https-proxy-agent` and `http-proxy-agent` do, is read as a proxy
 * for that scheme. Any other agent is opaque: this cannot tell a keep-alive
 * agent from a tunnelling one, so it reads nothing and the README says so.
 */
export function resolveProxyHost(url: URL, config: ProxyRelevantConfig): string | undefined {
  if (config.proxy === false) {
    return undefined;
  }

  if (config.proxy !== undefined && config.proxy !== null) {
    const { host, port } = config.proxy;

    return hostAndPort(host, port);
  }

  const agent = url.protocol === 'https:' ? config.httpsAgent : config.httpAgent;
  const fromAgent = agentProxy(agent);

  if (fromAgent !== undefined) {
    return fromAgent;
  }

  return proxyFromEnvironment(url);
}

/** `host:port`, lowercased, in the form a binding entry is written. */
function hostAndPort(host: string, port: number | undefined): string {
  const lower = host.toLowerCase();

  return port === undefined || Number.isNaN(port) ? lower : `${lower}:${port}`;
}

function agentProxy(agent: unknown): string | undefined {
  if (agent === null || typeof agent !== 'object' || !('proxy' in agent)) {
    return undefined;
  }

  const { proxy } = agent;

  if (proxy instanceof URL) {
    return proxy.host;
  }

  if (typeof proxy === 'string') {
    try {
      return new URL(proxy.includes('://') ? proxy : `http://${proxy}`).host;
    } catch {
      return undefined;
    }
  }

  return undefined;
}

const DEFAULT_PORTS: Readonly<Record<string, number>> = {
  http: 80,
  https: 443,
  ws: 80,
  wss: 443,
  ftp: 21,
};

function env(key: string): string {
  return process.env[key.toLowerCase()] ?? process.env[key.toUpperCase()] ?? '';
}

/**
 * `proxy-from-env`'s `getProxyForUrl`, restated.
 *
 * `no_proxy` is honoured exactly as that library reads it: `*` disables
 * proxying, an entry with a port applies only to that port, an entry with a
 * leading `.` or `*` matches by suffix, and any other entry matches exactly.
 */
function proxyFromEnvironment(url: URL): string | undefined {
  const scheme = url.protocol.slice(0, -1);
  const hostname = url.host.replace(/:\d*$/, '');
  const port = Number.parseInt(url.port, 10) || DEFAULT_PORTS[scheme] || 0;

  if (!shouldProxy(hostname, port)) {
    return undefined;
  }

  const proxy = env(`${scheme}_proxy`) || env('all_proxy');

  if (proxy === '') {
    return undefined;
  }

  try {
    return new URL(proxy.includes('://') ? proxy : `${scheme}://${proxy}`).host;
  } catch {
    // axios would fail to build the proxy URL too; the request goes nowhere.
    return undefined;
  }
}

function shouldProxy(hostname: string, port: number): boolean {
  const noProxy = env('no_proxy').toLowerCase();

  if (noProxy === '') {
    return true;
  }

  if (noProxy === '*') {
    return false;
  }

  return noProxy.split(/[,\s]/).every((entry) => {
    if (entry === '') {
      return true;
    }

    const withPort = /^(.+):(\d+)$/.exec(entry);
    let entryHost = withPort ? withPort[1]! : entry;
    const entryPort = withPort ? Number.parseInt(withPort[2]!, 10) : 0;

    if (entryPort !== 0 && entryPort !== port) {
      return true;
    }

    if (!/^[.*]/.test(entryHost)) {
      return hostname !== entryHost;
    }

    if (entryHost.startsWith('*')) {
      entryHost = entryHost.slice(1);
    }

    return !hostname.endsWith(entryHost);
  });
}
