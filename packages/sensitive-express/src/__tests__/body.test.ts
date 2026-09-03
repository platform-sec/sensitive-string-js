import { SensitiveString } from '@platform-sec/sensitive-string-core';
import express from 'express';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { sensitiveBody } from '../body.js';
import { CANARY, OTHER_CANARY, bodyOf, capture, createTestApp } from './fixtures.js';

describe('sensitiveBody', () => {
  // TEST-EXP-001
  it('wraps configured body fields as SensitiveString', async () => {
    const seen = capture<unknown>();
    const { app } = createTestApp((app) => {
      app.use(express.json());
      app.use(sensitiveBody({ fields: { password: 'credential' } }));
      app.post('/test', (req, res) => {
        seen.set(bodyOf(req)['password']);
        res.sendStatus(200);
      });
    });

    await request(app).post('/test').send({ password: CANARY }).expect(200);

    const wrapped = seen.get();

    expect(wrapped).toBeInstanceOf(SensitiveString);
    expect((wrapped as SensitiveString<'credential'>).klass).toBe('credential');
    expect((wrapped as SensitiveString<'credential'>).label).toBe('password');
  });

  // TEST-EXP-002
  it('reaches nested objects and array indices, labelling by the last segment', async () => {
    const seen = capture<Record<string, unknown>>();
    const { app } = createTestApp((app) => {
      app.use(express.json());
      app.use(
        sensitiveBody({
          fields: {
            'user.email': 'sensitive',
            'creditCard.cvv': 'credential',
            'items.0.secret': 'credential',
          },
        })
      );
      app.post('/test', (req, res) => {
        seen.set(req.body as Record<string, unknown>);
        res.sendStatus(200);
      });
    });

    await request(app)
      .post('/test')
      .send({
        user: { email: CANARY, name: 'plain' },
        creditCard: { cvv: '123', number: '4111111111111111' },
        items: [{ secret: OTHER_CANARY }, { secret: 'not configured' }],
      })
      .expect(200);

    const body = seen.get();
    const user = body['user'] as { email: SensitiveString<'sensitive'>; name: string };
    const card = body['creditCard'] as { cvv: SensitiveString<'credential'>; number: string };
    const items = body['items'] as { secret: unknown }[];

    expect(user.email).toBeInstanceOf(SensitiveString);
    expect(user.email.label).toBe('email');
    expect(user.name).toBe('plain');

    expect(card.cvv).toBeInstanceOf(SensitiveString);
    expect(card.cvv.label).toBe('cvv');
    expect(card.number).toBe('4111111111111111');

    expect(items[0]?.secret).toBeInstanceOf(SensitiveString);
    expect(items[1]?.secret).toBe('not configured');
  });

  // TEST-EXP-003
  it('takes an explicit label from an object config', async () => {
    const seen = capture<SensitiveString<'sensitive'>>();
    const { app } = createTestApp((app) => {
      app.use(express.json());
      app.use(
        sensitiveBody({
          fields: { 'user.taxIdentifier': { klass: 'sensitive', label: 'ssn' } },
        })
      );
      app.post('/test', (req, res) => {
        seen.set(
          (req.body as { user: { taxIdentifier: SensitiveString<'sensitive'> } }).user.taxIdentifier
        );
        res.sendStatus(200);
      });
    });

    await request(app)
      .post('/test')
      .send({ user: { taxIdentifier: CANARY } })
      .expect(200);

    expect(seen.get().label).toBe('ssn');
    expect(seen.get().klass).toBe('sensitive');
  });

  // TEST-EXP-004
  it('applies only under the path it is mounted on', async () => {
    const auth = capture<unknown>();
    const publicRoute = capture<unknown>();
    const { app } = createTestApp((app) => {
      app.use(express.json());
      app.use('/api/auth', sensitiveBody({ fields: { password: 'credential' } }));
      app.post('/api/auth/login', (req, res) => {
        auth.set(bodyOf(req)['password']);
        res.sendStatus(200);
      });
      app.post('/public/echo', (req, res) => {
        publicRoute.set(bodyOf(req)['password']);
        res.sendStatus(200);
      });
    });

    await request(app).post('/api/auth/login').send({ password: CANARY }).expect(200);
    await request(app).post('/public/echo').send({ password: CANARY }).expect(200);

    expect(auth.get()).toBeInstanceOf(SensitiveString);
    expect(publicRoute.get()).toBe(CANARY);
  });

  // TEST-EXP-005
  it('leaves a body whose content type is not configured alone', async () => {
    const seen = capture<unknown>();
    const { app } = createTestApp((app) => {
      app.use(express.json());
      app.use(express.urlencoded({ extended: true }));
      app.use(
        sensitiveBody({
          fields: { password: 'credential' },
          contentTypes: ['application/json'],
        })
      );
      app.post('/test', (req, res) => {
        seen.set(bodyOf(req)['password']);
        res.sendStatus(200);
      });
    });

    await request(app).post('/test').type('form').send({ password: CANARY }).expect(200);

    expect(seen.get()).toBe(CANARY);
  });

  it('processes urlencoded bodies under the default content types', async () => {
    const seen = capture<unknown>();
    const { app } = createTestApp((app) => {
      app.use(express.urlencoded({ extended: true }));
      app.use(sensitiveBody({ fields: { password: 'credential' } }));
      app.post('/test', (req, res) => {
        seen.set(bodyOf(req)['password']);
        res.sendStatus(200);
      });
    });

    await request(app).post('/test').type('form').send({ password: CANARY }).expect(200);

    expect(seen.get()).toBeInstanceOf(SensitiveString);
  });

  // TEST-EXP-EDGE-001
  it('ignores a configured field the body does not carry', async () => {
    const seen = capture<Record<string, unknown>>();
    const { app } = createTestApp((app) => {
      app.use(express.json());
      app.use(sensitiveBody({ fields: { password: 'credential', 'a.b.c': 'sensitive' } }));
      app.post('/test', (req, res) => {
        seen.set(req.body as Record<string, unknown>);
        res.sendStatus(200);
      });
    });

    await request(app).post('/test').send({ username: 'alice' }).expect(200);

    expect(seen.get()).toEqual({ username: 'alice' });
    expect('password' in seen.get()).toBe(false);
    expect('a' in seen.get()).toBe(false);
  });

  // TEST-EXP-EDGE-002
  it('leaves a non-string value at a configured path as it is', async () => {
    const seen = capture<Record<string, unknown>>();
    const { app } = createTestApp((app) => {
      app.use(express.json());
      app.use(
        sensitiveBody({
          fields: {
            pin: 'credential',
            enabled: 'sensitive',
            profile: 'sensitive',
            missing: 'sensitive',
          },
        })
      );
      app.post('/test', (req, res) => {
        seen.set(req.body as Record<string, unknown>);
        res.sendStatus(200);
      });
    });

    await request(app)
      .post('/test')
      .send({ pin: 1234, enabled: true, profile: { nested: 'value' }, missing: null })
      .expect(200);

    expect(seen.get()).toEqual({
      pin: 1234,
      enabled: true,
      profile: { nested: 'value' },
      missing: null,
    });
  });

  // TEST-EXP-EDGE-003
  it('passes an absent or empty body through untouched', async () => {
    const onGet = capture<unknown>();
    const onEmpty = capture<unknown>();
    const { app } = createTestApp((app) => {
      app.use(express.json());
      app.use(sensitiveBody({ fields: { password: 'credential' } }));
      app.get('/test', (req, res) => {
        onGet.set(req.body);
        res.sendStatus(200);
      });
      app.post('/test', (req, res) => {
        onEmpty.set(req.body);
        res.sendStatus(200);
      });
    });

    await request(app).get('/test').expect(200);
    await request(app).post('/test').send({}).expect(200);

    // Express 5 leaves an unparsed body undefined; Express 4 leaves it `{}`.
    expect(onGet.get() === undefined || onGet.get() === null).toBe(true);
    expect(onEmpty.get()).toEqual({});
  });

  // TEST-EXP-EDGE-004
  it('does not double-wrap when mounted globally and again per route', async () => {
    const seen = capture<SensitiveString<'credential'>>();
    const fields = { password: 'credential' } as const;
    const { app } = createTestApp((app) => {
      app.use(express.json());
      app.use(sensitiveBody({ fields }));
      app.post('/test', sensitiveBody({ fields }), (req, res) => {
        seen.set(bodyOf(req)['password'] as SensitiveString<'credential'>);
        res.sendStatus(200);
      });
    });

    await request(app).post('/test').send({ password: CANARY }).expect(200);

    const wrapped = seen.get();

    expect(wrapped).toBeInstanceOf(SensitiveString);
    // A second wrap would have produced a SensitiveString holding the redaction
    // of the first, so the raw value is the assertion that it did not happen.
    expect(wrapped.reveal({ name: 'test' })).toBe(CANARY);
  });

  // TEST-EXP-EDGE-005
  it('wraps configured fields in a large nested body', async () => {
    const records = Array.from({ length: 2000 }, (_, index) => ({
      id: index,
      note: 'x'.repeat(200),
    }));
    const seen = capture<Record<string, unknown>>();
    const { app } = createTestApp((app) => {
      app.use(express.json({ limit: '10mb' }));
      app.use(
        sensitiveBody({ fields: { 'account.token': 'credential', 'records.0.note': 'sensitive' } })
      );
      app.post('/test', (req, res) => {
        seen.set(req.body as Record<string, unknown>);
        res.sendStatus(200);
      });
    });

    // No wall-clock assertion: a duration verdict depends on how busy the
    // machine is, which is why this repository keeps timing measurements in
    // their own opt-in suite. What is asserted is that a body of this size
    // still wraps correctly inside the 10s test timeout.
    await request(app)
      .post('/test')
      .send({ account: { token: CANARY }, records })
      .expect(200);

    const body = seen.get();
    const account = body['account'] as { token: unknown };
    const wrapped = body['records'] as { note: unknown }[];

    expect(account.token).toBeInstanceOf(SensitiveString);
    expect(wrapped[0]?.note).toBeInstanceOf(SensitiveString);
    expect(wrapped[1]?.note).toBe('x'.repeat(200));
    expect(wrapped).toHaveLength(2000);
  });

  describe('configuration validation', () => {
    it('rejects an entry that is not a sensitivity class', () => {
      expect(() =>
        sensitiveBody({ fields: { password: 'secret' as unknown as 'credential' } })
      ).toThrow(TypeError);
    });

    it('rejects a path with an empty segment', () => {
      expect(() => sensitiveBody({ fields: { 'user..email': 'sensitive' } })).toThrow(
        /empty path segment/
      );
    });

    it('rejects a path that walks a prototype key', () => {
      expect(() => sensitiveBody({ fields: { '__proto__.polluted': 'sensitive' } })).toThrow(
        /reserved segment/
      );
      expect(() => sensitiveBody({ fields: { 'a.constructor.b': 'sensitive' } })).toThrow(
        /reserved segment/
      );
    });

    it('rejects a non-string label', () => {
      expect(() =>
        sensitiveBody({
          fields: { password: { klass: 'credential', label: 7 as unknown as string } },
        })
      ).toThrow(/label must be a string/);
    });

    it('fails at construction rather than on the first request', () => {
      // The whole point of validating in the factory: a typo in a field map is
      // a startup failure, not a field that quietly never gets wrapped.
      expect(() => sensitiveBody({ fields: { '': 'sensitive' } })).toThrow(/empty path key/);
    });
  });
});
