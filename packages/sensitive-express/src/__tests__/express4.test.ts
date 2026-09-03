import { SensitiveString } from '@platform-sec/sensitive-string-core';
import express4 from 'express4';
import express4Manifest from 'express4/package.json';
import type express from 'express';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { sensitiveBody } from '../body.js';
import { sensitiveContext } from '../context.js';
import { sensitiveHeaders } from '../headers.js';
import { sensitiveResponseFilter } from '../response-filter.js';
import { stripParseErrorBody } from '../parse-error.js';
import { CANARY, OTHER_CANARY, bodyOf, capture } from './fixtures.js';

/**
 * A smoke test rather than a second copy of the suite.
 *
 * The peer range claims Express 4, and three surfaces diverge between the
 * majors: `req.body` is `{}` on 4 and `undefined` on 5 when nothing was parsed,
 * `req.query` is writable on 4 and a getter on 5, and `/api/auth/*` is a valid
 * route pattern on 4 and rejected by path-to-regexp 8 on 5. This package avoids
 * the second and third by construction; the first is what the body middleware
 * has to tolerate, and it is asserted below.
 */
describe('express 4', () => {
  it('resolves the alias to Express 4', () => {
    expect(express4Manifest.version.startsWith('4.')).toBe(true);
  });

  it('runs the whole middleware stack', async () => {
    const seen = capture<Record<string, unknown>>();
    const app = express4();
    const errors: unknown[] = [];

    app.use(express4.json());
    app.use(stripParseErrorBody());
    app.use(sensitiveContext((req) => ({ name: `${req.method} ${req.path}` })));
    app.use(sensitiveHeaders({ fields: { authorization: 'credential' } }));
    app.use(sensitiveResponseFilter());
    app.use('/api/auth', sensitiveBody({ fields: { password: 'credential' } }));

    app.post('/api/auth/login', (req, res) => {
      seen.set(bodyOf(req));
      res.json({ echo: bodyOf(req), auth: req.sensitive.headers['authorization'] });
    });

    app.use(((err, _req, res, _next) => {
      errors.push(err);
      res.sendStatus(500);
    }) as express.ErrorRequestHandler);

    const response = await request(app)
      .post('/api/auth/login')
      .set('Authorization', `Bearer ${OTHER_CANARY}`)
      .send({ password: CANARY })
      .expect(200);

    expect(seen.get()['password']).toBeInstanceOf(SensitiveString);
    expect(response.body).toEqual({
      echo: { password: '[REDACTED:credential]' },
      auth: '[REDACTED:credential]',
    });
    expect(response.text).not.toContain(CANARY);
    expect(response.text).not.toContain(OTHER_CANARY);
    expect(errors).toEqual([]);
  });

  it('treats the empty body Express 4 leaves behind as nothing to wrap', async () => {
    const seen = capture<unknown>();
    const app = express4();

    app.use(express4.json());
    app.use(sensitiveBody({ fields: { password: 'credential' } }));
    app.get('/test', (req, res) => {
      seen.set(req.body);
      res.sendStatus(200);
    });

    await request(app).get('/test').expect(200);

    // `{}` on Express 4 where Express 5 leaves `undefined`. Both mean the same
    // thing to this middleware, and neither is an error.
    expect(seen.get()).toEqual({});
  });

  it('scrubs the raw body from an Express 4 parse error', async () => {
    const app = express4();
    const errors: unknown[] = [];

    app.use(express4.json());
    app.use(stripParseErrorBody());
    app.post('/test', (_req, res) => {
      res.sendStatus(200);
    });
    app.use(((err, _req, res, _next) => {
      errors.push(err);
      res.sendStatus(400);
    }) as express.ErrorRequestHandler);

    await request(app)
      .post('/test')
      .set('Content-Type', 'application/json')
      .send(`{"password":"${CANARY}",}`)
      .expect(400);

    expect(errors).toHaveLength(1);
    expect('body' in (errors[0] as object)).toBe(false);
  });
});
