import {
  SensitiveString,
  getCurrentRevealContext,
  safeStringify,
  type RevealContext,
} from '@platform-sec/sensitive-string-core';
import express from 'express';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { sensitiveBody } from '../body.js';
import { sensitiveContext } from '../context.js';
import { sensitiveHeaders } from '../headers.js';
import { CANARY, bodyOf, capture, createTestApp } from './fixtures.js';

describe('integration', () => {
  // TEST-EXP-INT-001
  it('wraps nested fields in an extended urlencoded body', async () => {
    const seen = capture<Record<string, unknown>>();
    const { app } = createTestApp((app) => {
      app.use(express.urlencoded({ extended: true }));
      app.use(sensitiveBody({ fields: { 'user.password': 'credential' } }));
      app.post('/test', (req, res) => {
        seen.set(req.body as Record<string, unknown>);
        res.sendStatus(200);
      });
    });

    await request(app)
      .post('/test')
      .type('form')
      .send({ user: { password: CANARY, name: 'alice' } })
      .expect(200);

    const user = seen.get()['user'] as { password: unknown; name: string };

    expect(user.password).toBeInstanceOf(SensitiveString);
    expect(user.name).toBe('alice');
  });

  // TEST-EXP-INT-002
  it('keeps the context across an await in an async handler', async () => {
    const before = capture<RevealContext | null>();
    const after = capture<RevealContext | null>();
    const { app } = createTestApp((app) => {
      app.use(sensitiveContext(() => ({ name: 'request' })));
      app.get('/test', async (_req, res) => {
        before.set(getCurrentRevealContext());
        await new Promise((resolve) => setTimeout(resolve, 5));
        after.set(getCurrentRevealContext());
        res.sendStatus(200);
      });
    });

    await request(app).get('/test').expect(200);

    expect(before.get()?.name).toBe('request');
    expect(after.get()?.name).toBe('request');
  });

  // TEST-EXP-INT-003
  it('keeps the context in an error handler reached from a rejected async handler', async () => {
    const seen = capture<RevealContext | null>();
    const logged = capture<string>();
    const { app } = createTestApp((app) => {
      app.use(express.json());
      app.use(sensitiveContext(() => ({ name: 'request' })));
      app.use(sensitiveBody({ fields: { password: 'credential' } }));
      app.post('/test', async (_req, _res) => {
        await Promise.resolve();
        throw new Error('handler failed');
      });
      app.use(((err: unknown, req: express.Request, res: express.Response, _next: unknown) => {
        seen.set(getCurrentRevealContext());
        logged.set(safeStringify({ err: String(err), body: bodyOf(req) }));
        res.status(500).json({ error: 'failed' });
      }) as express.ErrorRequestHandler);
    });

    await request(app).post('/test').send({ password: CANARY }).expect(500);

    expect(seen.get()?.name).toBe('request');
    expect(logged.get()).not.toContain(CANARY);
    expect(logged.get()).toContain('[REDACTED:credential]');
  });

  // TEST-EXP-INT-004
  it('works on a Router mounted under a prefix', async () => {
    const onRouter = capture<unknown>();
    const outside = capture<unknown>();
    const { app } = createTestApp((app) => {
      const router = express.Router();

      router.use(sensitiveBody({ fields: { password: 'credential' } }));
      router.use(sensitiveHeaders({ fields: { 'x-api-key': 'credential' } }));
      router.post('/login', (req, res) => {
        onRouter.set(bodyOf(req)['password']);
        res.json({ auth: req.sensitive.headers['x-api-key'] });
      });

      app.use(express.json());
      app.use('/api/auth', router);
      app.post('/other', (req, res) => {
        outside.set(bodyOf(req)['password']);
        res.sendStatus(200);
      });
    });

    const response = await request(app)
      .post('/api/auth/login')
      .set('X-Api-Key', CANARY)
      .send({ password: CANARY })
      .expect(200);

    await request(app).post('/other').send({ password: CANARY }).expect(200);

    expect(onRouter.get()).toBeInstanceOf(SensitiveString);
    expect(outside.get()).toBe(CANARY);
    expect(response.text).not.toContain(CANARY);
  });

  // TEST-EXP-INT-005
  it('documents the ordering rule against a string validator', async () => {
    const requireStringPassword: express.RequestHandler = (req, res, next) => {
      if (typeof (req.body as { password?: unknown })?.password !== 'string') {
        res.status(400).json({ error: 'password must be a string' });
        return;
      }

      next();
    };

    const { app } = createTestApp((app) => {
      app.use(express.json());

      // Validator first: it sees a plain string and passes.
      app.post(
        '/correct',
        requireStringPassword,
        sensitiveBody({ fields: { password: 'credential' } }),
        (req, res) => {
          res.json({ wrapped: bodyOf(req)['password'] instanceof SensitiveString });
        }
      );

      // Validator second: it sees a SensitiveString and rejects. This is the
      // failure mode the middleware-order table warns about.
      app.post(
        '/inverted',
        sensitiveBody({ fields: { password: 'credential' } }),
        requireStringPassword,
        (_req, res) => {
          res.json({ reached: true });
        }
      );
    });

    const correct = await request(app).post('/correct').send({ password: CANARY }).expect(200);

    expect(correct.body).toEqual({ wrapped: true });

    await request(app)
      .post('/inverted')
      .send({ password: CANARY })
      .expect(400)
      .expect((response) => {
        expect(response.body).toEqual({ error: 'password must be a string' });
      });
  });
});
