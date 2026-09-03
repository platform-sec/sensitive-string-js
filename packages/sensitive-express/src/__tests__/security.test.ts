import { SensitiveString, type SensitivityClass } from '@platform-sec/sensitive-string-core';
import { expectNotLeaked, findRawValue } from '@platform-sec/sensitive-string-testing';
import express from 'express';
import request from 'supertest';
import { inspect } from 'node:util';
import { describe, expect, it } from 'vitest';
import { sensitiveBody } from '../body.js';
import { sensitiveHeaders } from '../headers.js';
import { sensitiveResponseFilter } from '../response-filter.js';
import { stripParseErrorBody } from '../parse-error.js';
import { CANARY, OTHER_CANARY, UserEntity, bodyOf, capture, createTestApp } from './fixtures.js';

/** The malformed payload the parse-error tests post: a trailing comma. */
const MALFORMED = `{"password":"${CANARY}",}`;

describe('security', () => {
  // TEST-EXP-SEC-001
  it('CANARY: req.body does not leak through stringify or inspect', async () => {
    const json = capture<string>();
    const inspected = capture<string>();
    const { app } = createTestApp((app) => {
      app.use(express.json());
      app.use(sensitiveBody({ fields: { password: 'credential', 'user.email': 'sensitive' } }));
      app.post('/test', (req, res) => {
        json.set(JSON.stringify(req.body));
        inspected.set(inspect(req.body, { depth: null }));
        res.sendStatus(200);
      });
    });

    await request(app)
      .post('/test')
      .send({ password: CANARY, user: { email: OTHER_CANARY } })
      .expect(200);

    expect(json.get()).not.toContain(CANARY);
    expect(json.get()).not.toContain(OTHER_CANARY);
    expect(json.get()).toContain('[REDACTED:credential]');
    expect(json.get()).toContain('[REDACTED:sensitive]');

    expect(inspected.get()).not.toContain(CANARY);
    expect(inspected.get()).not.toContain(OTHER_CANARY);
  });

  // TEST-EXP-SEC-002
  it('CANARY: a nested array of entities does not leak through the response', async () => {
    const email = new SensitiveString(CANARY, 'sensitive', 'email');
    const apiKey = new SensitiveString(OTHER_CANARY, 'credential', 'api_key');
    const { app } = createTestApp((app) => {
      app.use(sensitiveResponseFilter());
      app.get('/test', (_req, res) => {
        res.json({ page: 1, results: [{ user: new UserEntity(1, email, apiKey) }] });
      });
    });

    const response = await request(app).get('/test').expect(200);

    expectNotLeaked(email, response.text, response.body);
    expectNotLeaked(apiKey, response.text, response.body);
    expect(response.text).toContain('[REDACTED:sensitive]');
    expect(response.text).toContain('[REDACTED:credential]');
  });

  // TEST-EXP-SEC-003
  it('CANARY: a serialized value in a response is redacted', async () => {
    const token = new SensitiveString(CANARY, 'credential', 'token');
    const { app } = createTestApp((app) => {
      app.use(sensitiveResponseFilter());
      app.get('/test', (_req, res) => {
        res.json({ token: token.serialize() });
      });
    });

    const response = await request(app).get('/test').expect(200);

    expectNotLeaked(token, response.text, response.body);
    expect(response.text).toContain('[REDACTED:credential]');
  });

  it('documents the leak: a serialized value without the filter is sent whole', async () => {
    const token = new SensitiveString(CANARY, 'credential', 'token');
    const { app } = createTestApp((app) => {
      app.get('/test', (_req, res) => {
        res.json({ token: token.serialize() });
      });
    });

    const response = await request(app).get('/test').expect(200);

    // This is why the filter exists: toJSON() never runs on a plain object that
    // merely carries the marker, and JSON.stringify emits the raw value.
    expect(response.text).toContain(CANARY);
  });

  // TEST-EXP-SEC-004
  it('CANARY: a parse error carries no body once scrubbed', async () => {
    const { app, errors } = createTestApp((app) => {
      app.use(express.json());
      app.use(stripParseErrorBody());
      app.post('/test', (_req, res) => {
        res.sendStatus(200);
      });
    });

    await request(app)
      .post('/test')
      .set('Content-Type', 'application/json')
      .send(MALFORMED)
      .expect(400);

    expect(errors).toHaveLength(1);

    const err = errors[0] as Record<string, unknown>;

    expect('body' in err && err['body'] !== undefined).toBe(false);
    expect(inspect(err, { depth: null })).not.toContain(CANARY);
    expect(findRawValue(err, CANARY)).toBeUndefined();

    // The rest of the error survives, so the application's own handler still
    // sees what body-parser decided.
    expect(err['status']).toBe(400);
    expect(err['type']).toBe('entity.parse.failed');
  });

  it('documents the leak: the same parse error without the scrubber carries the body', async () => {
    const { app, errors } = createTestApp((app) => {
      app.use(express.json());
      app.post('/test', (_req, res) => {
        res.sendStatus(200);
      });
    });

    await request(app)
      .post('/test')
      .set('Content-Type', 'application/json')
      .send(MALFORMED)
      .expect(400);

    const err = errors[0] as Record<string, unknown>;

    expect(err['body']).toContain(CANARY);
  });

  it('does not send the parse error body to the client either way', async () => {
    const { app } = createTestApp((app) => {
      app.use(express.json());
      app.use(stripParseErrorBody());
      app.post('/test', (_req, res) => {
        res.sendStatus(200);
      });
    });

    const response = await request(app)
      .post('/test')
      .set('Content-Type', 'application/json')
      .send(MALFORMED)
      .expect(400);

    expect(response.text).not.toContain(CANARY);
  });

  it('passes a non-parse error through untouched', async () => {
    const original = new Error('boom');
    const { app, errors } = createTestApp((app) => {
      app.use(stripParseErrorBody());
      app.get('/test', () => {
        throw original;
      });
    });

    await request(app).get('/test').expect(500);

    expect(errors[0]).toBe(original);
  });

  // TEST-EXP-SEC-006
  it('CANARY: sensitiveHeaders leaves the raw header readable where Express looks', async () => {
    const raw = capture<unknown>();
    const wrapped = capture<SensitiveString<SensitivityClass> | null | undefined>();
    const { app } = createTestApp((app) => {
      app.use(sensitiveHeaders({ fields: { authorization: 'credential' } }));
      app.get('/test', (req, res) => {
        raw.set(req.headers.authorization);
        wrapped.set(req.sensitive.headers['authorization']);
        res.json({ ok: true });
      });
    });

    const response = await request(app)
      .get('/test')
      .set('Authorization', `Bearer ${CANARY}`)
      .expect(200);

    // The documented trade-off, asserted rather than assumed: the raw header is
    // still there for req.get(), for Passport, and for a logger that dumps
    // req.headers. Only the wrapped copy redacts.
    expect(raw.get()).toBe(`Bearer ${CANARY}`);
    expect(String(wrapped.get())).toBe('[REDACTED:credential]');
    expect(response.text).not.toContain(CANARY);
  });

  it('CANARY: the whole stack keeps the canary out of every response surface', async () => {
    const { app } = createTestApp((app) => {
      app.use(express.json());
      app.use(stripParseErrorBody());
      app.use(sensitiveHeaders({ fields: { authorization: 'credential' } }));
      app.use(sensitiveResponseFilter());
      app.use(sensitiveBody({ fields: { password: 'credential' } }));
      app.post('/test', (req, res) => {
        // Echoing the request body back is the mistake this package is meant to
        // survive.
        res.json({ echo: bodyOf(req), auth: req.sensitive.headers['authorization'] });
      });
    });

    const response = await request(app)
      .post('/test')
      .set('Authorization', `Bearer ${OTHER_CANARY}`)
      .send({ password: CANARY })
      .expect(200);

    expect(response.text).not.toContain(CANARY);
    expect(response.text).not.toContain(OTHER_CANARY);
    expect(response.body).toEqual({
      echo: { password: '[REDACTED:credential]' },
      auth: '[REDACTED:credential]',
    });
  });
});
