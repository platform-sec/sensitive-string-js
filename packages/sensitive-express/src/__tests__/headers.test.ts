import { SensitiveString, type SensitiveFieldConfig } from '@platform-sec/sensitive-string-core';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { sensitiveHeaders } from '../headers.js';
import type { SensitiveRequest } from '../types.js';
import { CANARY, OTHER_CANARY, capture, createTestApp } from './fixtures.js';

const FIELDS = {
  authorization: 'credential',
  'x-api-key': { klass: 'credential', label: 'api_key' },
  'x-absent': 'sensitive',
  'x-empty': 'sensitive',
} as const;

describe('sensitiveHeaders', () => {
  // TEST-EXP-006
  it('places wrapped copies on req.sensitive.headers', async () => {
    const seen = capture<SensitiveRequest['headers']>();
    const { app } = createTestApp((app) => {
      app.use(sensitiveHeaders({ fields: FIELDS }));
      app.get('/test', (req, res) => {
        seen.set(req.sensitive.headers);
        res.sendStatus(200);
      });
    });

    await request(app)
      .get('/test')
      .set('Authorization', `Bearer ${CANARY}`)
      .set('X-Api-Key', OTHER_CANARY)
      .set('X-Empty', '')
      .expect(200);

    const headers = seen.get();
    const auth = headers['authorization'];
    const apiKey = headers['x-api-key'];

    expect(auth).toBeInstanceOf(SensitiveString);
    expect(auth?.klass).toBe('credential');
    expect(auth?.label).toBe('authorization');
    expect(auth?.reveal({ name: 'test' })).toBe(`Bearer ${CANARY}`);

    expect(apiKey).toBeInstanceOf(SensitiveString);
    expect(apiKey?.label).toBe('api_key');

    // fromOptional turns both of these into null, so an empty header is not
    // mistaken for a credential of length zero.
    expect(headers['x-absent']).toBeNull();
    expect(headers['x-empty']).toBeNull();
  });

  it('matches configured names case-insensitively and reads them back lower case', async () => {
    const seen = capture<SensitiveRequest['headers']>();
    const { app } = createTestApp((app) => {
      app.use(sensitiveHeaders({ fields: { 'X-Api-Key': 'credential' } }));
      app.get('/test', (req, res) => {
        seen.set(req.sensitive.headers);
        res.sendStatus(200);
      });
    });

    await request(app).get('/test').set('x-API-key', CANARY).expect(200);

    expect(seen.get()['x-api-key']).toBeInstanceOf(SensitiveString);
    expect(seen.get()['x-api-key']?.label).toBe('x-api-key');
  });

  // TEST-EXP-EDGE-006
  it('wraps the first element of a repeated header', async () => {
    const seen = capture<SensitiveRequest['headers']>();
    const { app } = createTestApp((app) => {
      // Node joins most repeated request headers with a comma, and keeps
      // `set-cookie` and anything a middleware assigns in array form. Assigning
      // one is how a test reaches that shape, and it is the shape the wrapper
      // has to survive rather than wrap into a `[object Object]`.
      app.use((req, _res, next) => {
        req.headers['x-forwarded-for'] = [CANARY, OTHER_CANARY];
        next();
      });
      app.use(sensitiveHeaders({ fields: { 'x-forwarded-for': 'sensitive' } }));
      app.get('/test', (req, res) => {
        seen.set(req.sensitive.headers);
        res.sendStatus(200);
      });
    });

    await request(app).get('/test').expect(200);

    const forwarded = seen.get()['x-forwarded-for'];

    expect(forwarded).toBeInstanceOf(SensitiveString);
    expect(forwarded?.reveal({ name: 'test' })).toBe(CANARY);
  });

  // TEST-EXP-SEC-006
  it('leaves req.headers untouched', async () => {
    const raw = capture<unknown>();
    const viaGet = capture<unknown>();
    const { app } = createTestApp((app) => {
      app.use(sensitiveHeaders({ fields: { authorization: 'credential' } }));
      app.get('/test', (req, res) => {
        raw.set(req.headers.authorization);
        viaGet.set(req.get('authorization'));
        res.sendStatus(200);
      });
    });

    await request(app).get('/test').set('Authorization', `Bearer ${CANARY}`).expect(200);

    expect(raw.get()).toBe(`Bearer ${CANARY}`);
    expect(viaGet.get()).toBe(`Bearer ${CANARY}`);
  });

  it('adds to the container a previous mount created rather than replacing it', async () => {
    const seen = capture<SensitiveRequest['headers']>();
    const { app } = createTestApp((app) => {
      app.use(sensitiveHeaders({ fields: { authorization: 'credential' } }));
      app.use(sensitiveHeaders({ fields: { 'x-api-key': 'credential' } }));
      app.get('/test', (req, res) => {
        seen.set(req.sensitive.headers);
        res.sendStatus(200);
      });
    });

    await request(app)
      .get('/test')
      .set('Authorization', CANARY)
      .set('X-Api-Key', OTHER_CANARY)
      .expect(200);

    expect(seen.get()['authorization']).toBeInstanceOf(SensitiveString);
    expect(seen.get()['x-api-key']).toBeInstanceOf(SensitiveString);
  });

  it('keeps a header named after a prototype key out of Object.prototype', async () => {
    // Assigned rather than written as a literal: `constructor` in a fresh
    // object literal takes its type from `Object`, not from the index
    // signature it is being checked against.
    const fields: SensitiveFieldConfig = {};
    fields['constructor'] = 'sensitive';
    const seen = capture<SensitiveRequest['headers']>();
    const { app } = createTestApp((app) => {
      app.use(sensitiveHeaders({ fields }));
      app.get('/test', (req, res) => {
        seen.set(req.sensitive.headers);
        res.sendStatus(200);
      });
    });

    await request(app).get('/test').set('constructor', CANARY).expect(200);

    expect(seen.get()['constructor']).toBeInstanceOf(SensitiveString);
    expect(Object.getPrototypeOf(seen.get())).toBeNull();
  });

  it('rejects a malformed field map at construction', () => {
    expect(() =>
      sensitiveHeaders({ fields: { authorization: 'bearer' as unknown as 'credential' } })
    ).toThrow(TypeError);
  });
});
