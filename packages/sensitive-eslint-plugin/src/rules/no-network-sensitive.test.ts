import { describe } from 'vitest';
import { noNetworkSensitive } from './no-network-sensitive.js';
import { runRuleTests, runTypeScriptRuleTests } from '../__tests__/rule-tester.js';

describe('no-network-sensitive', () => {
  runRuleTests('no-network-sensitive', noNetworkSensitive, {
    valid: [
      // The wire format keeps the shape under the library's control.
      'fetch(url, { body: JSON.stringify({ token: token.serialize() }) });',
      'axios.post(url, { token: token.serialize() });',

      // An audited reveal is a deliberate, recorded transmission. This is the
      // design document's own example of correct code.
      "fetch(url, { headers: { Authorization: token.reveal({ name: 'auth-header' }) } });",
      "axios.post(url, { token: token.reveal({ name: 'gateway', reason: 'charging' }) });",
      'got.post(url, { json: { token: token.reveal(ctx) } });',

      // Not a network call.
      'authenticate(token.reveal());',
      'db.query(sql, [token.reveal()]);',
      'cache.set(key, token.reveal());',

      // A network call carrying no reveal.
      'fetch(url, { body: JSON.stringify(publicPayload) });',
      'fetch(url);',

      // Fastify names its request object `request`, so the name is not a
      // network client by default.
      'request.headers.authorization = token.reveal();',
    ],

    invalid: [
      {
        code: 'fetch(url, { body: secret.reveal() });',
        errors: [{ messageId: 'noNetworkReveal' }],
      },
      {
        code: 'axios.post(url, { token: token.reveal() });',
        errors: [{ messageId: 'noNetworkReveal' }],
      },
      // Reached through a builder chain.
      {
        code: 'superagent.post(url).send({ token: token.reveal() });',
        errors: [{ messageId: 'noNetworkReveal' }],
      },
      {
        code: 'https.request(options, cb).end(token.reveal());',
        errors: [{ messageId: 'noNetworkReveal' }],
      },
      // Interpolated into the URL.
      {
        code: 'fetch(`https://api.example/?token=${token.reveal()}`);',
        errors: [{ messageId: 'noNetworkReveal' }],
      },
      // Deeply nested in the options object.
      {
        code: 'fetch(url, { headers: { Authorization: `Bearer ${token.reveal()}` } });',
        errors: [{ messageId: 'noNetworkReveal' }],
      },
      // Every unaudited reveal in the call is reported.
      {
        code: 'fetch(url, { headers: { a: a.reveal() }, body: b.reveal() });',
        errors: [{ messageId: 'noNetworkReveal' }, { messageId: 'noNetworkReveal' }],
      },
      // An audited reveal alongside an unaudited one reports only the second.
      {
        code: "fetch(url, { headers: { a: a.reveal({ name: 'h' }) }, body: b.reveal() });",
        errors: [{ messageId: 'noNetworkReveal' }],
      },
      // A placeholder argument is not an audit context, so it must not be what
      // lets the value onto the wire.
      {
        code: 'fetch(url, { body: secret.reveal(undefined) });',
        errors: [{ messageId: 'noNetworkReveal' }],
      },
      {
        code: 'fetch(url, { body: secret.reveal(void 0) });',
        errors: [{ messageId: 'noNetworkReveal' }],
      },

      // A client the project names itself.
      {
        code: 'apiClient.post(url, { token: token.reveal() });',
        options: [{ networkFunctions: ['apiClient'] }],
        errors: [{ messageId: 'noNetworkReveal' }],
      },
      // serialize() is the recommended transmission path, so it is never
      // reported here even though no-log-reveal treats it as a leak.
      {
        code: 'fetch(url, { body: token.reveal(), extra: token.serialize() });',
        errors: [{ messageId: 'noNetworkReveal' }],
      },
    ],
  });

  describe('allowWithContext: false', () => {
    runRuleTests('no-network-sensitive', noNetworkSensitive, {
      valid: [
        {
          code: 'fetch(url, { body: JSON.stringify({ token: token.serialize() }) });',
          options: [{ allowWithContext: false }],
        },
      ],
      invalid: [
        // The exemption is gone: an audited reveal is reported too.
        {
          code: "fetch(url, { headers: { Authorization: token.reveal({ name: 'auth-header' }) } });",
          options: [{ allowWithContext: false }],
          errors: [{ messageId: 'noNetworkRevealStrict' }],
        },
        {
          code: 'fetch(url, { body: secret.reveal() });',
          options: [{ allowWithContext: false }],
          errors: [{ messageId: 'noNetworkRevealStrict' }],
        },
      ],
    });
  });

  describe('under the TypeScript parser', () => {
    runTypeScriptRuleTests('no-network-sensitive', noNetworkSensitive, {
      valid: ["await fetch(url, { headers: { a: token.reveal({ name: 'h' }) } });"],
      invalid: [
        {
          code: 'await fetch(url, { body: secret!.reveal() });',
          errors: [{ messageId: 'noNetworkReveal' }],
        },
        {
          code: 'await fetch(url, { body: secret.reveal() as string });',
          errors: [{ messageId: 'noNetworkReveal' }],
        },
      ],
    });
  });
});
