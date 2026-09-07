import { describe } from 'vitest';
import { noPasswordFastHash } from './no-password-fast-hash.js';
import { runRuleTests, runTypeScriptRuleTests } from '../__tests__/rule-tester.js';

describe('no-password-fast-hash', () => {
  runRuleTests('no-password-fast-hash', noPasswordFastHash, {
    valid: [
      // The values hash() is for.
      "token.hash('sha256');",
      "secret.hash('sha256', { salt });",
      "apiKey.hmac('sha256', key);",
      "email.hmac('sha256', correlationKey);",

      // The name that matters is the value being hashed, not what holds it.
      "passwordService.token.hash('sha256');",
      "passwordStore.apiKey.hmac('sha256', key);",

      // The right thing to do with a password, in both spellings.
      'bcrypt.hash(password, 12);',
      'hashForStorage(password, { algorithm: 4 });',
      'argon2.hash(password);',

      // Other methods on a password are this rule's business only if they hash.
      "password.reveal({ name: 'login' });",
      'password.equals(input);',
      'password.mask();',

      // A narrowed configuration must narrow.
      {
        code: "password.hash('sha256');",
        options: [{ passwordNames: ['secretPhrase'] }],
      },
    ],

    invalid: [
      {
        code: "password.hash('sha256');",
        errors: [{ messageId: 'fastHash', data: { method: 'hash' } }],
      },
      {
        code: "user.password.hash('sha256');",
        errors: [{ messageId: 'fastHash', data: { method: 'hash' } }],
      },
      {
        code: "this.password.hash('sha512');",
        errors: [{ messageId: 'fastHash', data: { method: 'hash' } }],
      },
      // The fragment matches inside a longer name, in any case.
      {
        code: "newPassword.hash('sha256');",
        errors: [{ messageId: 'fastHash', data: { method: 'hash' } }],
      },
      {
        code: "plainPWD.hash('sha256');",
        errors: [{ messageId: 'fastHash', data: { method: 'hash' } }],
      },
      {
        code: "credentials.passwd.hash('sha256');",
        errors: [{ messageId: 'fastHash', data: { method: 'hash' } }],
      },
      {
        code: "passphrase.hmac('sha256', pepper);",
        errors: [{ messageId: 'fastHash', data: { method: 'hmac' } }],
      },
      // A key does not make a fast function slow.
      {
        code: "password.hmac('sha512', pepper);",
        errors: [{ messageId: 'fastHash', data: { method: 'hmac' } }],
      },
      // Reached through a call rather than a name.
      {
        code: "getPassword().hash('sha256');",
        errors: [{ messageId: 'fastHash', data: { method: 'hash' } }],
      },
      // Computed and optional forms reach the same method.
      {
        code: "password['hash']('sha256');",
        errors: [{ messageId: 'fastHash', data: { method: 'hash' } }],
      },
      {
        code: "password?.hash('sha256');",
        errors: [{ messageId: 'fastHash', data: { method: 'hash' } }],
      },
      // A configured list replaces the default rather than extending it.
      {
        code: "secretPhrase.hash('sha256');",
        options: [{ passwordNames: ['secretPhrase'] }],
        errors: [{ messageId: 'fastHash', data: { method: 'hash' } }],
      },
    ],
  });

  describe('under the TypeScript parser', () => {
    runTypeScriptRuleTests('no-password-fast-hash', noPasswordFastHash, {
      valid: ["const stored = await hashForStorage(password, { algorithm: 'argon2id' });"],
      invalid: [
        {
          code: "const digest = (password as SensitiveString).hash('sha256');",
          errors: [{ messageId: 'fastHash', data: { method: 'hash' } }],
        },
        {
          code: "const digest = password!.hash('sha256');",
          errors: [{ messageId: 'fastHash', data: { method: 'hash' } }],
        },
      ],
    });
  });
});
