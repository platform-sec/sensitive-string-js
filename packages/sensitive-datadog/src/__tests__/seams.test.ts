import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import { COVERED_PLUGINS, DEFERRED_PLUGINS, knownPlugins } from '../seams.js';
import { AGENT_VERSION, agentRequire } from './fixtures.js';

/**
 * The seam inventory, read off the agent's own declarations.
 *
 * The Sentry package pins its seams with a type-level exhaustiveness check
 * over a `before${string}` family. There is no such family here: a `dd-trace`
 * hook is a `hooks` property on one plugin's options interface, and there are
 * 85 plugin interfaces. So this reads the shipped `index.d.ts`, resolves the
 * interface inheritance, and fails when a plugin offers a hook that neither
 * `COVERED_PLUGINS` nor `DEFERRED_PLUGINS` has an opinion about.
 *
 * Weaker than the Sentry check, since it is a runtime read of a declaration
 * file rather than a compile-time constraint, and it catches the same failure:
 * a plugin gaining a hook in a minor release and this package silently not
 * covering it.
 *
 * Measured against `dd-trace` 6.14.0 on Node 22.15.0.
 */

/** One plugin id and the hook names its options interface offers. */
type HookMap = Map<string, Set<string>>;

/**
 * Read every plugin that offers a `hooks` option, inheritance resolved.
 *
 * Inheritance is the whole reason this is a parser rather than a grep. Eight
 * interfaces declare `hooks` directly; `express`, `fastify`, `koa`, `connect`,
 * `hapi`, `hono`, `restify` and `microgateway_core` extend `HttpServer` and
 * `fetch` and `undici` extend `HttpClient`, and every one of them takes the
 * inherited `hooks.request`. Counting only the direct declarations gives 9 and
 * misses the plugins most deployments actually run.
 */
function readHookPlugins(): HookMap {
  const source = readFileSync(agentRequire().resolve('dd-trace/index.d.ts'), 'utf8');
  const lines = source.split('\n');

  const declared = new Map<string, Set<string>>();
  const parents = new Map<string, string[]>();
  const stack: { name: string; depth: number }[] = [];

  let depth = 0;
  let collecting: { owner: string; depth: number } | null = null;

  for (const line of lines) {
    const declaration =
      /^\s*(?:export\s+)?interface\s+([A-Za-z0-9_$]+)\s*(?:extends\s+([^{]+))?/.exec(line);

    if (declaration?.[1] !== undefined) {
      stack.push({ name: declaration[1], depth });
      parents.set(
        declaration[1],
        (declaration[2] ?? '')
          .split(',')
          .map((name) => name.trim())
          .filter((name) => name !== '')
      );
    }

    const owner = stack.at(-1);

    if (/^\s*hooks\?\s*:/.test(line) && owner !== undefined) {
      collecting = { owner: owner.name, depth };

      if (!declared.has(owner.name)) {
        declared.set(owner.name, new Set());
      }
    } else if (collecting !== null) {
      const member = /^\s*([a-zA-Z0-9_$]+)\?\s*:/.exec(line);

      // Only members at the hook block's own depth. A multi-line signature
      // puts its parameter names on their own lines and they look identical.
      if (member?.[1] !== undefined && depth === collecting.depth + 1) {
        declared.get(collecting.owner)?.add(member[1]);
      }

      if (/^\s*\}/.test(line) && depth <= collecting.depth + 1) {
        collecting = null;
      }
    }

    for (const character of line) {
      if (character === '{') {
        depth += 1;
      } else if (character === '}') {
        depth -= 1;

        while (stack.length > 0 && (stack.at(-1)?.depth ?? 0) >= depth) {
          stack.pop();
        }
      }
    }
  }

  const resolve = (name: string, seen = new Set<string>()): Set<string> => {
    if (seen.has(name)) {
      return new Set();
    }
    seen.add(name);

    const hooks = new Set(declared.get(name) ?? []);

    for (const parent of parents.get(name) ?? []) {
      for (const hook of resolve(parent, seen)) {
        hooks.add(hook);
      }
    }

    return hooks;
  };

  const found: HookMap = new Map();

  for (const [id, iface] of pluginInterfaces(lines)) {
    const hooks = resolve(iface);

    if (hooks.size > 0) {
      found.set(id, hooks);
    }
  }

  return found;
}

/** Every `<plugin id>: tracer.plugins.<Interface>` member of the `Plugins` interface. */
function pluginInterfaces(lines: readonly string[]): [string, string][] {
  const start = lines.findIndex((line) => /^\s*interface Plugins\s*\{/.test(line));

  if (start === -1) {
    throw new Error(
      'the Plugins interface was not found in dd-trace/index.d.ts. The declarations have ' +
        'been restructured and this reader must be re-taken by hand.'
    );
  }

  const found: [string, string][] = [];

  for (let index = start + 1; index < lines.length; index += 1) {
    if (/^\s{2,4}\}/.test(lines[index] ?? '')) {
      break;
    }

    const member = /^\s*"?([a-zA-Z0-9_$@/-]+)"?\s*:\s*tracer\.plugins\.([A-Za-z0-9_$]+)/.exec(
      lines[index] ?? ''
    );

    if (member?.[1] !== undefined && member[2] !== undefined) {
      found.push([member[1], member[2]]);
    }
  }

  return found;
}

describe(`the seam inventory against dd-trace ${AGENT_VERSION}`, () => {
  const offered = readHookPlugins();

  it('reads the declarations at all, so a silent empty comparison cannot pass', () => {
    expect(offered.size).toBeGreaterThan(10);
    expect([...offered.keys()]).toContain('http');
  });

  it('finds every plugin the design named, plus the ones it inherits to', () => {
    const ids = [...offered.keys()].sort();

    expect(ids).toContain('apollo');
    expect(ids).toContain('aws-sdk');
    expect(ids).toContain('elasticsearch');
    expect(ids).toContain('graphql');
    expect(ids).toContain('next');
    expect(ids).toContain('sharedb');
    expect(ids).toContain('undici');

    // The correction the measurement forced. Every one of these takes an
    // inherited `hooks.request`, and `express.request` carries the raw
    // `authorization` header when only `http` is covered.
    expect(ids).toContain('express');
    expect(ids).toContain('fastify');
    expect(ids).toContain('koa');
    expect(ids).toContain('fetch');
  });

  it('has an opinion about every plugin that offers a hook', () => {
    const known = knownPlugins();
    const uncovered = [...offered.keys()].filter((id) => !known.has(id)).sort();

    expect(uncovered, buildFailure(uncovered)).toEqual([]);
  });

  it('covers the request hook on every plugin it claims to cover', () => {
    for (const covered of COVERED_PLUGINS) {
      const hooks = offered.get(covered.plugin);

      expect(hooks, `${covered.plugin} offers no hooks at all`).toBeDefined();

      for (const hook of covered.hooks) {
        expect([...(hooks ?? [])], `${covered.plugin} has no ${hook} hook`).toContain(hook);
      }
    }
  });

  it('names no plugin the agent does not have', () => {
    const stale = [...knownPlugins()].filter((id) => !offered.has(id) && id !== 'web').sort();

    expect(stale).toEqual([]);
  });

  it('records a reason for every plugin it defers', () => {
    for (const [plugin, reason] of Object.entries(DEFERRED_PLUGINS)) {
      expect(reason.length, `${plugin} is deferred with no reason`).toBeGreaterThan(10);
    }
  });

  it('does not both cover and defer a plugin', () => {
    const covered = new Set(COVERED_PLUGINS.map((entry) => entry.plugin));
    const both = Object.keys(DEFERRED_PLUGINS).filter((plugin) => covered.has(plugin));

    expect(both).toEqual([]);
  });
});

/** What the failure says, since a bare empty-array diff names nothing useful. */
function buildFailure(uncovered: readonly string[]): string {
  if (uncovered.length === 0) {
    return '';
  }

  return (
    `dd-trace offers a hooks option on ${uncovered.join(', ')}, and this package has no ` +
    'opinion about it. Add it to COVERED_PLUGINS with a hook body, or to DEFERRED_PLUGINS ' +
    'with the reason it is not covered.'
  );
}
