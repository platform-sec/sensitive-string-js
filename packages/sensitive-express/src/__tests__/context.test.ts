import {
  SensitiveString,
  getCurrentRevealContext,
  type RevealContext,
  type RevealDetails,
} from '@platform-sec/sensitive-string-core';
import express from 'express';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { sensitiveBody } from '../body.js';
import { sensitiveContext } from '../context.js';
import { CANARY, bodyOf, capture, createTestApp } from './fixtures.js';

describe('sensitiveContext', () => {
  // TEST-EXP-007
  it('makes the factory context current for the handler', async () => {
    const seen = capture<RevealContext | null>();
    const { app } = createTestApp((app) => {
      app.use(
        sensitiveContext((req) => ({
          name: `${req.method} ${req.path}`,
          tags: { requestId: req.headers['x-request-id'] },
        }))
      );
      app.get('/test', (_req, res) => {
        seen.set(getCurrentRevealContext());
        res.sendStatus(200);
      });
    });

    await request(app).get('/test').set('x-request-id', 'req-42').expect(200);

    expect(seen.get()?.name).toBe('GET /test');
    expect(seen.get()?.tags).toEqual({ requestId: 'req-42' });
  });

  it('establishes no context when the factory returns undefined', async () => {
    const seen = capture<RevealContext | null>();
    const { app } = createTestApp((app) => {
      app.use(sensitiveContext(() => undefined));
      app.get('/test', (_req, res) => {
        seen.set(getCurrentRevealContext());
        res.sendStatus(200);
      });
    });

    await request(app).get('/test').expect(200);

    // Not an empty context: a policy whose checkRevealAllowed rejects a missing
    // context has to keep rejecting.
    expect(seen.get()).toBeNull();
  });

  it('covers middleware registered after it', async () => {
    const seen = capture<RevealContext | null>();
    const { app } = createTestApp((app) => {
      app.use(sensitiveContext(() => ({ name: 'request' })));
      app.use((_req, _res, next) => {
        seen.set(getCurrentRevealContext());
        next();
      });
      app.get('/test', (_req, res) => {
        res.sendStatus(200);
      });
    });

    await request(app).get('/test').expect(200);

    expect(seen.get()?.name).toBe('request');
  });

  it('does not cover middleware registered before it', async () => {
    const seen = capture<RevealContext | null>();
    const { app } = createTestApp((app) => {
      app.use((_req, _res, next) => {
        seen.set(getCurrentRevealContext());
        next();
      });
      app.use(sensitiveContext(() => ({ name: 'request' })));
      app.get('/test', (_req, res) => {
        res.sendStatus(200);
      });
    });

    await request(app).get('/test').expect(200);

    expect(seen.get()).toBeNull();
  });

  it('reaches an error handler after a synchronous throw', async () => {
    const seen = capture<RevealContext | null>();
    const { app } = createTestApp((app) => {
      app.use(sensitiveContext(() => ({ name: 'request' })));
      app.get('/test', () => {
        throw new Error('sync boom');
      });
      app.use(((_err: unknown, _req: unknown, res: express.Response, _next: unknown) => {
        seen.set(getCurrentRevealContext());
        res.sendStatus(500);
      }) as express.ErrorRequestHandler);
    });

    await request(app).get('/test').expect(500);

    // Express catches a synchronous throw at the layer that threw, so the
    // next(err) it makes still runs inside the scope this middleware opened.
    expect(seen.get()?.name).toBe('request');
  });

  it('reaches an error handler after next(err) from later middleware', async () => {
    const seen = capture<RevealContext | null>();
    const { app } = createTestApp((app) => {
      app.use(sensitiveContext(() => ({ name: 'request' })));
      app.use((_req, _res, next) => {
        next(new Error('passed along'));
      });
      app.use(((_err: unknown, _req: unknown, res: express.Response, _next: unknown) => {
        seen.set(getCurrentRevealContext());
        res.sendStatus(500);
      }) as express.ErrorRequestHandler);
    });

    await request(app).get('/test').expect(500);

    expect(seen.get()?.name).toBe('request');
  });

  it('covers a response listener that fires while the handler is still running', async () => {
    const seen = capture<RevealContext | null>();
    const { app } = createTestApp((app) => {
      app.use(sensitiveContext(() => ({ name: 'request' })));
      app.get('/test', (_req, res) => {
        res.on('finish', () => {
          seen.set(getCurrentRevealContext());
        });
        res.sendStatus(200);
      });
    });

    await request(app).get('/test').expect(200);
    await new Promise((resolve) => setTimeout(resolve, 20));

    // An event listener is a plain function: it runs in whatever context is
    // active when the event fires, not the one active where it was registered.
    // `finish` for a small body is emitted from inside `res.end()`, which is
    // still inside the scope. A listener that fires after the scope has
    // unwound gets nothing, which is why reveal() off the request path passes
    // an explicit context.
    expect(seen.get()?.name).toBe('request');
  });

  // TEST-EXP-SEC-005
  it('routes an audit record from a handler reveal to the request context', async () => {
    const records: {
      operation: string;
      klass: string;
      label: string | undefined;
      tags: unknown;
    }[] = [];
    const { app } = createTestApp((app) => {
      app.use(express.json());
      app.use(
        sensitiveContext((req) => ({
          name: `${req.method} ${req.path}`,
          tags: { requestId: req.headers['x-request-id'] },
          auditReveal: (value, details: RevealDetails) => {
            records.push({
              operation: details.operation,
              klass: value.klass,
              label: value.label,
              tags: { requestId: req.headers['x-request-id'] },
            });
          },
        }))
      );
      app.use(sensitiveBody({ fields: { password: 'credential' } }));
      app.post('/test', (req, res) => {
        (bodyOf(req)['password'] as SensitiveString<'credential'>).reveal();
        res.sendStatus(200);
      });
    });

    await request(app)
      .post('/test')
      .set('x-request-id', 'req-7')
      .send({ password: CANARY })
      .expect(200);

    expect(records).toHaveLength(1);
    expect(records[0]).toEqual({
      operation: 'reveal',
      klass: 'credential',
      label: 'password',
      tags: { requestId: 'req-7' },
    });
  });

  it('does not leak the revealed value into the audit record', async () => {
    const records: unknown[] = [];
    const { app } = createTestApp((app) => {
      app.use(express.json());
      app.use(
        sensitiveContext(() => ({
          name: 'request',
          auditReveal: (value, details) => {
            records.push({ klass: value.klass, label: value.label, details, value });
          },
        }))
      );
      app.use(sensitiveBody({ fields: { password: 'credential' } }));
      app.post('/test', (req, res) => {
        (bodyOf(req)['password'] as SensitiveString<'credential'>).reveal();
        res.sendStatus(200);
      });
    });

    await request(app).post('/test').send({ password: CANARY }).expect(200);

    expect(JSON.stringify(records)).not.toContain(CANARY);
  });
});
