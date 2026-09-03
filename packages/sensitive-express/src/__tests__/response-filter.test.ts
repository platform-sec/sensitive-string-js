import { SensitiveString } from '@platform-sec/sensitive-string-core';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { sensitiveResponseFilter } from '../response-filter.js';
import {
  CANARY,
  OTHER_CANARY,
  ProfileEntity,
  UserEntity,
  capture,
  captureJsonBody,
  createTestApp,
} from './fixtures.js';

describe('sensitiveResponseFilter', () => {
  // TEST-EXP-008
  it('redacts a SensitiveString in a JSON response', async () => {
    const { app } = createTestApp((app) => {
      app.use(sensitiveResponseFilter());
      app.get('/test', (_req, res) => {
        res.json({
          id: 1,
          apiKey: new SensitiveString(CANARY, 'credential', 'api_key'),
        });
      });
    });

    const response = await request(app).get('/test').expect(200);

    expect(response.body).toEqual({ id: 1, apiKey: '[REDACTED:credential]' });
    expect(response.text).not.toContain(CANARY);
  });

  it('covers res.send(object), which Express routes through res.json', async () => {
    const { app } = createTestApp((app) => {
      app.use(sensitiveResponseFilter());
      app.get('/test', (_req, res) => {
        res.send({ apiKey: new SensitiveString(CANARY, 'credential') });
      });
    });

    const response = await request(app).get('/test').expect(200);

    expect(response.body).toEqual({ apiKey: '[REDACTED:credential]' });
    expect(response.text).not.toContain(CANARY);
  });

  it('covers res.jsonp, which serializes without going through res.json', async () => {
    const { app } = createTestApp((app) => {
      app.use(sensitiveResponseFilter());
      app.get('/test', (_req, res) => {
        res.jsonp({ apiKey: new SensitiveString(CANARY, 'credential') });
      });
    });

    const response = await request(app).get('/test').query({ callback: 'cb' }).expect(200);

    expect(response.text).not.toContain(CANARY);
    expect(response.text).toContain('[REDACTED:credential]');
    expect(response.text).toContain('cb(');
  });

  it('redacts a serialized value, which JSON.stringify would emit faithfully', async () => {
    const secret = new SensitiveString(CANARY, 'credential', 'token');
    const { app } = createTestApp((app) => {
      app.use(sensitiveResponseFilter());
      app.get('/test', (_req, res) => {
        res.json({ token: secret.serialize() });
      });
    });

    const response = await request(app).get('/test').expect(200);

    expect(response.body).toEqual({ token: '[REDACTED:credential]' });
    expect(response.text).not.toContain(CANARY);
  });

  // TEST-EXP-009
  it('keeps an entity prototype, so its toJSON still runs after the walk', async () => {
    const { app } = createTestApp((app) => {
      app.use(sensitiveResponseFilter());
      app.get('/test', (_req, res) => {
        res.json(new ProfileEntity(9, new SensitiveString(CANARY, 'sensitive', 'email')));
      });
    });

    const response = await request(app).get('/test').expect(200);

    expect(response.body).toEqual({
      kind: 'profile',
      id: 9,
      email: '[REDACTED:sensitive]',
    });
    expect(response.text).not.toContain(CANARY);
  });

  it('leaves a plain string alone, revealed or not', async () => {
    const secret = new SensitiveString(CANARY, 'credential');
    const { app } = createTestApp((app) => {
      app.use(sensitiveResponseFilter());
      app.get('/json', (_req, res) => {
        // Revealed into a plain string: indistinguishable from any other text,
        // and sent, by design.
        res.json({ token: secret.reveal({ name: 'test' }) });
      });
      app.get('/send', (_req, res) => {
        res.type('text/plain').send(secret.reveal({ name: 'test' }));
      });
    });

    await request(app)
      .get('/json')
      .expect(200)
      .expect((response) => {
        expect(response.text).toContain(CANARY);
      });
    await request(app)
      .get('/send')
      .expect(200)
      .expect((response) => {
        expect(response.text).toBe(CANARY);
      });
  });

  // TEST-EXP-EDGE-007
  it('keeps a shared reference shared in the redacted copy', async () => {
    const seen = capture<unknown>();
    const shared = { apiKey: new SensitiveString(CANARY, 'credential') };
    const { app } = createTestApp((app) => {
      // Registered first, so the filter binds and calls this one: the redacted
      // copy is only observable as an object from here.
      app.use(captureJsonBody(seen));
      app.use(sensitiveResponseFilter());
      app.get('/test', (_req, res) => {
        res.json({ a: shared, b: shared });
      });
    });

    await request(app).get('/test').expect(200);

    const body = seen.get() as { a: unknown; b: unknown };

    expect(body.a).toBe(body.b);
    expect(body.a).not.toBe(shared);
    expect(body.a).toEqual({ apiKey: '[REDACTED:credential]' });
  });

  it('leaves a cyclic body failing at JSON.stringify, as it would unfiltered', async () => {
    const cyclic: Record<string, unknown> = { apiKey: new SensitiveString(CANARY, 'credential') };
    cyclic['self'] = cyclic;

    const { app, errors } = createTestApp((app) => {
      app.use(sensitiveResponseFilter());
      app.get('/test', (_req, res) => {
        res.json(cyclic);
      });
    });

    await request(app).get('/test').expect(500);

    expect(errors).toHaveLength(1);
    expect(String(errors[0])).toMatch(/circular|cyclic/i);
    expect(String(errors[0])).not.toContain(CANARY);
  });

  it('walks the body once when mounted more than once', async () => {
    const walked = capture<unknown>();
    const { app } = createTestApp((app) => {
      app.use(captureJsonBody(walked));
      app.use(sensitiveResponseFilter());
      app.use(sensitiveResponseFilter());
      app.get('/test', (_req, res) => {
        res.json({ apiKey: new SensitiveString(CANARY, 'credential') });
      });
    });

    const response = await request(app).get('/test').expect(200);

    expect(response.body).toEqual({ apiKey: '[REDACTED:credential]' });
    expect(walked.get()).toEqual({ apiKey: '[REDACTED:credential]' });
  });

  it('passes a body with nothing sensitive through unchanged in shape', async () => {
    const { app } = createTestApp((app) => {
      app.use(sensitiveResponseFilter());
      app.get('/test', (_req, res) => {
        res.json({ items: [1, 2, 3], nested: { ok: true }, when: new Date(0).toISOString() });
      });
    });

    const response = await request(app).get('/test').expect(200);

    expect(response.body).toEqual({
      items: [1, 2, 3],
      nested: { ok: true },
      when: '1970-01-01T00:00:00.000Z',
    });
  });

  it('redacts instances nested inside arrays of entities', async () => {
    const { app } = createTestApp((app) => {
      app.use(sensitiveResponseFilter());
      app.get('/test', (_req, res) => {
        res.json({
          users: [
            new UserEntity(
              1,
              new SensitiveString(CANARY, 'sensitive', 'email'),
              new SensitiveString(OTHER_CANARY, 'credential', 'api_key')
            ),
          ],
        });
      });
    });

    const response = await request(app).get('/test').expect(200);

    expect(response.body).toEqual({
      users: [{ id: 1, email: '[REDACTED:sensitive]', apiKey: '[REDACTED:credential]' }],
    });
    expect(response.text).not.toContain(CANARY);
    expect(response.text).not.toContain(OTHER_CANARY);
  });
});
