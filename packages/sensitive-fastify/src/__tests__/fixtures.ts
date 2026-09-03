import type { SensitiveString } from '@platform-sec/sensitive-string-core';
import Fastify, { type FastifyInstance, type FastifyServerOptions } from 'fastify';
import { sensitiveKeyword } from '../keyword.js';

/**
 * The canary every leak assertion looks for. One constant, so a test that
 * forgets to assert absence is visible next to one that does.
 */
export const CANARY = 'LEAKED_SECRET_abc123xyz';

/** A second canary, for a test that needs two distinguishable values. */
export const OTHER_CANARY = 'LEAKED_SECRET_def456uvw';

/** A login body schema using the keyword on both properties. */
export const LOGIN_SCHEMA = {
  body: {
    type: 'object',
    required: ['email', 'password'],
    properties: {
      email: { type: 'string', format: 'email', sensitive: { klass: 'sensitive' } },
      password: { type: 'string', minLength: 8, sensitive: { klass: 'credential' } },
    },
  },
} as const;

/** The body shape `LOGIN_SCHEMA` produces once the keyword has run. */
export interface LoginBody {
  email: SensitiveString<'sensitive'>;
  password: SensitiveString<'credential'>;
}

/**
 * A Fastify instance with the keyword registered, which is the only place it can
 * be registered: Ajv is built with the instance.
 */
export function buildApp(options: FastifyServerOptions = {}): FastifyInstance {
  return Fastify({
    ...options,
    ajv: { customOptions: { keywords: [sensitiveKeyword] } },
  });
}

/** An instance with no keyword, for the field-map and plugin-only suites. */
export function buildPlainApp(options: FastifyServerOptions = {}): FastifyInstance {
  return Fastify(options);
}

/** A Fastify instance whose log lines are collected rather than printed. */
export function buildLoggingApp(): { app: FastifyInstance; lines: string[] } {
  const lines: string[] = [];

  const app = buildApp({
    logger: {
      level: 'info',
      stream: {
        write(line: string) {
          lines.push(line);
        },
      },
    },
  });

  return { app, lines };
}

/**
 * Record whatever a handler saw, for assertion after the request resolves.
 *
 * An `expect` that throws inside a handler becomes a 500, and the status
 * expectation then reports the wrong status rather than the real failure. Every
 * suite here captures instead, and asserts once `inject` has returned.
 */
export function capture<T>(): { set(value: T): void; get(): T } {
  let held: T | undefined;
  let assigned = false;

  return {
    set(value: T) {
      held = value;
      assigned = true;
    },
    get(): T {
      if (!assigned) {
        throw new Error('capture() was never set: the handler did not run');
      }

      return held as T;
    },
  };
}

/** `request.body` as an inspectable record. */
export function bodyOf(body: unknown): Record<string, unknown> {
  return body as Record<string, unknown>;
}

/** Stands in for an ORM entity: a class instance, not a plain object. */
export class UserEntity {
  constructor(
    readonly id: number,
    readonly email: SensitiveString<'sensitive'>,
    readonly apiKey: SensitiveString<'credential'>
  ) {}
}

/** An entity that decides its own serialized shape. */
export class ProfileEntity {
  constructor(
    readonly id: number,
    readonly email: SensitiveString<'sensitive'>
  ) {}

  toJSON() {
    return { kind: 'profile', id: this.id, email: this.email };
  }
}
