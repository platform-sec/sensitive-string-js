import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { promisify } from 'node:util';
import { describe, expect, test } from 'vitest';
import { sensitivePlugin } from '../plugin.js';
import { bodyOf, buildApp, buildPlainApp, CANARY, capture, LOGIN_SCHEMA } from './fixtures.js';

const execFileAsync = promisify(execFile);

/**
 * This package's directory.
 *
 * Located by walking up to the workspace root rather than from the module's own
 * path, because neither `import.meta.url` nor `__dirname` exists under both the
 * Vitest transform and the NodeNext CommonJS type-check, and the suite runs
 * from the repository root and from the package directory alike. Same approach
 * as `sensitive-eslint-plugin`'s manifest lookup.
 */
function findPackageRoot(): string {
  let directory = process.cwd();

  for (;;) {
    if (existsSync(path.join(directory, 'pnpm-workspace.yaml'))) {
      return path.join(directory, 'packages', 'sensitive-fastify');
    }

    const parent = path.dirname(directory);

    if (parent === directory) {
      throw new Error(`Could not find the workspace root above ${process.cwd()}.`);
    }

    directory = parent;
  }
}

const packageRoot = findPackageRoot();

describe('hook ordering against other plugins', () => {
  // TEST-FST-INT-002
  test('a preValidation hook sees strings, the same hook at route level sees instances', async () => {
    const app = buildPlainApp();
    const atPreValidation = capture<unknown>();
    const atRouteLevel = capture<unknown>();

    await app.register(sensitivePlugin, { body: { password: 'credential' } });

    // A local authentication strategy reads the password as a string. Fastify's
    // own docs put `authenticate` at preValidation, which runs before the field
    // map, so it keeps working unchanged.
    app.addHook('preValidation', async (request) => {
      atPreValidation.set(bodyOf(request.body)['password']);
    });

    app.post(
      '/login',
      {
        // A route-level preHandler runs after every instance-level one, so it
        // receives the instance. This is the failure mode a strategy registered
        // here would hit, and the reason to move it to preValidation or to
        // reveal explicitly.
        preHandler: async (request) => {
          atRouteLevel.set(bodyOf(request.body)['password']);
        },
      },
      async () => ({ ok: true })
    );

    await app.inject({ method: 'POST', url: '/login', payload: { password: CANARY } });

    expect(atPreValidation.get()).toBe(CANARY);
    expect(atRouteLevel.get()).toBeInstanceOf(SensitiveString);
  });

  test('an instance hook registered before the plugin sees strings, one after sees instances', async () => {
    const app = buildPlainApp();
    const before = capture<unknown>();
    const after = capture<unknown>();

    app.addHook('preHandler', async (request) => {
      before.set(bodyOf(request.body)['password']);
    });

    await app.register(sensitivePlugin, { body: { password: 'credential' } });

    app.addHook('preHandler', async (request) => {
      after.set(bodyOf(request.body)['password']);
    });

    app.post('/login', async () => ({ ok: true }));

    await app.inject({ method: 'POST', url: '/login', payload: { password: CANARY } });

    expect(before.get()).toBe(CANARY);
    expect(after.get()).toBeInstanceOf(SensitiveString);
  });

  test('validation still sees plain strings on a field-map route', async () => {
    const app = buildApp();
    const seen = capture<unknown>();

    await app.register(sensitivePlugin, { body: { password: 'credential' } });

    // No `sensitive` keyword here: a plain schema, validated against strings.
    app.post(
      '/login',
      {
        schema: {
          body: {
            type: 'object',
            required: ['password'],
            properties: { password: { type: 'string', minLength: 8 } },
          },
        },
      },
      async (request) => {
        seen.set(request.body);

        return { ok: true };
      }
    );

    const ok = await app.inject({ method: 'POST', url: '/login', payload: { password: CANARY } });
    const short = await app.inject({ method: 'POST', url: '/login', payload: { password: 'ab' } });

    expect(ok.statusCode).toBe(200);
    expect(short.statusCode).toBe(400);
    expect(bodyOf(seen.get())['password']).toBeInstanceOf(SensitiveString);
  });
});

describe('encapsulation', () => {
  // TEST-FST-INT-004
  test('a prefixed registration covers its own routes and nothing outside', async () => {
    const app = buildApp();
    const inside = capture<unknown>();
    const outside = capture<unknown>();
    const rootHeaders = capture<unknown>();

    await app.register(
      async function billing(instance) {
        await instance.register(sensitivePlugin, {
          body: { 'card.number': 'credential' },
          headers: { 'x-api-key': 'credential' },
          responseFilter: true,
        });

        instance.post('/charge', async (request) => {
          inside.set(request.body);

          return { token: new SensitiveString(CANARY, 'credential').serialize() };
        });
      },
      { prefix: '/billing' }
    );

    await app.register(sensitivePlugin, {});

    app.post('/charge', async (request) => {
      outside.set(request.body);
      rootHeaders.set(request.sensitive.headers['x-api-key']);

      return { ok: true };
    });

    const payload = { card: { number: CANARY } };
    const scoped = await app.inject({
      method: 'POST',
      url: '/billing/charge',
      payload,
      headers: { 'x-api-key': CANARY },
    });
    const root = await app.inject({
      method: 'POST',
      url: '/charge',
      payload,
      headers: { 'x-api-key': CANARY },
    });

    expect(bodyOf(bodyOf(inside.get())['card'])['number']).toBeInstanceOf(SensitiveString);
    expect(bodyOf(bodyOf(outside.get())['card'])['number']).toBe(CANARY);

    // The response filter is scoped too.
    expect(scoped.body).not.toContain(CANARY);
    expect(root.statusCode).toBe(200);
    expect(rootHeaders.get()).toBeUndefined();
  });

  test('the keyword works on a route in a scope where the plugin is not registered', async () => {
    const app = buildApp();
    const seen = capture<unknown>();

    // The keyword lives in Ajv, which belongs to the instance rather than to a
    // plugin scope, so it applies everywhere the schema does.
    app.post('/login', { schema: LOGIN_SCHEMA }, async (request) => {
      seen.set(request.body);

      return { ok: true };
    });

    const response = await app.inject({
      method: 'POST',
      url: '/login',
      payload: { email: 'a@b.co', password: CANARY },
    });

    expect(response.statusCode).toBe(200);
    expect(bodyOf(seen.get())['password']).toBeInstanceOf(SensitiveString);
  });
});

describe('published types', () => {
  // TEST-FST-INT-005
  test('declaration merging and the keyword compile in a consumer-shaped fixture', async () => {
    // Resolved from this package rather than from the module's own path, for
    // the reason `findPackageRoot` gives. TypeScript is one of its own
    // devDependencies, so the lookup is local either way.
    const resolveFrom = createRequire(path.join(packageRoot, 'package.json'));
    const tsc = resolveFrom.resolve('typescript/bin/tsc');

    // `tsc --noEmit` over `src` plus the compile-only fixture. A type error in
    // a Vitest file never fails the runtime suite, and typescript-eslint
    // reports lint findings rather than type errors, so this spawn is the only
    // thing that actually checks the merged declarations from outside.
    await expect(
      execFileAsync(process.execPath, [tsc, '--noEmit', '-p', 'tsconfig.typecheck.json'], {
        cwd: packageRoot,
      })
    ).resolves.toMatchObject({ stdout: '' });
  }, 60_000);
});
