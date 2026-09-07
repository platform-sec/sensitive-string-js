import { describe } from 'vitest';
import { noAllowUnaudited } from './no-allow-unaudited.js';
import { runRuleTests, runTypeScriptRuleTests } from '../__tests__/rule-tester.js';

describe('no-allow-unaudited', () => {
  runRuleTests('no-allow-unaudited', noAllowUnaudited, {
    valid: [
      // The hook installed, which is what the flag would have skipped.
      'fromWorkerPayload(workerData, { auditReveal: (v, d) => log(v.klass, d) });',
      'withWorkerPayload(workerData, { auditReveal }, ({ token }) => token.reveal());',
      'fromWorkerPayload(workerData);',
      'withWorkerPayload(workerData, {}, run);',

      // The default spelled out, and an explicit absence.
      'fromWorkerPayload(workerData, { allowUnaudited: false });',
      'fromWorkerPayload(workerData, { allowUnaudited: undefined, auditReveal });',

      // Other options are not the flag.
      'fromWorkerPayload(workerData, { require: ["token"], keepPayload: true });',

      // The flag on a call that is not a payload consumer.
      'consume(workerData, { allowUnaudited: true });',
      'toWorkerPayload({ token }, { allowUnaudited: true });',

      // A flag reached through a variable is invisible to syntax, and the
      // documentation says so.
      'const options = { allowUnaudited: true };\nfromWorkerPayload(workerData, options);',

      // A computed key is not statically the flag.
      'fromWorkerPayload(workerData, { [flag]: true });',

      // The configured names replace the defaults.
      {
        code: 'fromWorkerPayload(workerData, { allowUnaudited: true });',
        options: [{ payloadFunctions: ['receivePayload'] }],
      },
    ],

    invalid: [
      {
        code: 'fromWorkerPayload(workerData, { allowUnaudited: true });',
        errors: [{ messageId: 'allowUnaudited', data: { function: 'fromWorkerPayload' } }],
      },
      {
        code: 'withWorkerPayload(workerData, { allowUnaudited: true }, ({ token }) => token.reveal());',
        errors: [{ messageId: 'allowUnaudited', data: { function: 'withWorkerPayload' } }],
      },
      {
        // A variable is still a deliberate setting of the flag.
        code: 'fromWorkerPayload(workerData, { allowUnaudited: skipAudit });',
        errors: [{ messageId: 'allowUnaudited' }],
      },
      {
        // A string key is the same key.
        code: "fromWorkerPayload(workerData, { 'allowUnaudited': true });",
        errors: [{ messageId: 'allowUnaudited' }],
      },
      {
        // Alongside a hook it is still the flag, and the hook does not excuse it.
        code: 'fromWorkerPayload(workerData, { auditReveal, allowUnaudited: true });',
        errors: [{ messageId: 'allowUnaudited' }],
      },
      {
        // Through a namespace or a member.
        code: 'core.fromWorkerPayload(workerData, { allowUnaudited: true });',
        errors: [{ messageId: 'allowUnaudited' }],
      },
      {
        // Behind a leading spread, which position-based reading would miss.
        code: 'fromWorkerPayload(...args, { allowUnaudited: true });',
        errors: [{ messageId: 'allowUnaudited' }],
      },
      {
        // The configured names replace the defaults.
        code: 'receivePayload(workerData, { allowUnaudited: true });',
        options: [{ payloadFunctions: ['receivePayload'] }],
        errors: [{ messageId: 'allowUnaudited', data: { function: 'receivePayload' } }],
      },
    ],
  });

  runTypeScriptRuleTests('no-allow-unaudited (typescript)', noAllowUnaudited, {
    valid: ['fromWorkerPayload<Values>(workerData, { auditReveal } as const);'],
    invalid: [
      {
        code: 'fromWorkerPayload<Values>(workerData, { allowUnaudited: true } as FromWorkerPayloadOptions);',
        errors: [{ messageId: 'allowUnaudited' }],
      },
      {
        code: 'withWorkerPayload(workerData!, ({ allowUnaudited: true }), run);',
        errors: [{ messageId: 'allowUnaudited' }],
      },
    ],
  });
});
