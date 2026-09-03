/**
 * Compile-only fixture for TEST-FST-INT-005.
 *
 * Nothing here runs. `types.test.ts` compiles this file with `tsc --noEmit` and
 * asserts a clean exit, which is the only way to check that the declaration
 * merging in `types.ts` reaches a consumer: a type error in a Vitest file is
 * invisible to the runtime suite, and typescript-eslint reports lint findings
 * rather than type errors.
 */
import type { SensitiveString } from '@platform-sec/sensitive-string-core';
import Fastify from 'fastify';
import { sensitiveKeyword, sensitivePlugin, type SensitiveRequest } from '../../index.js';

interface LoginBody {
  email: SensitiveString<'sensitive'>;
  password: SensitiveString<'credential'>;
}

const AUTH_FIELDS = {
  password: 'credential',
  email: { klass: 'sensitive', label: 'email' },
} as const;

export async function build() {
  const fastify = Fastify({
    ajv: { customOptions: { keywords: [sensitiveKeyword] } },
  });

  await fastify.register(sensitivePlugin, {
    body: AUTH_FIELDS,
    headers: { authorization: 'credential' },
    context: (request) => ({
      name: `${request.method} ${request.routeOptions.url ?? ''}`,
      tags: { requestId: request.id },
    }),
    contextHook: 'onRequest',
    responseFilter: true,
  });

  // A route declaring its body with SensitiveString fields, which is what the
  // keyword produces.
  fastify.post<{ Body: LoginBody }>(
    '/api/auth/login',
    {
      schema: {
        body: {
          type: 'object',
          required: ['email', 'password'],
          properties: {
            email: { type: 'string', format: 'email', sensitive: { klass: 'sensitive' } },
            password: { type: 'string', minLength: 8, sensitive: { klass: 'credential' } },
          },
        },
      },
    },
    async (request) => {
      const password: SensitiveString<'credential'> = request.body.password;

      // `request.sensitive` through declaration merging on FastifyRequest.
      const container: SensitiveRequest = request.sensitive;
      const auth: SensitiveString<'sensitive' | 'credential'> | null =
        container.headers['authorization'] ?? null;

      return { ok: password.klass === 'credential', auth: auth === null };
    }
  );

  // `config.sensitive` through declaration merging on FastifyContextConfig.
  fastify.post(
    '/api/keys',
    { config: { sensitive: { body: { apiKey: 'credential' } } } },
    async () => ({ ok: true })
  );

  return fastify;
}
