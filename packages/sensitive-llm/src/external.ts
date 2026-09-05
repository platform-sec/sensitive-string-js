import {
  createChildContext,
  getPolicy,
  SensitiveString,
  type SensitivityClass,
} from '@platform-sec/sensitive-string-core';

import type { SendToExternalOptions } from './types.js';

/**
 * The authorization gate for a value leaving the trust boundary.
 *
 * This is the feature. Everything else in this package reduces a payload or
 * derives a pseudonym; this is the only place where `advisory` stops being
 * documentation. The flag it reads, `allowSendToExternal`, was declared in
 * `core`'s `SensitivityAdvisory` from the beginning and read by nothing.
 *
 * The leak it addresses is not a value someone forgot to wrap. It is this:
 *
 * ```ts
 * const raw = key.reveal({ name: 'llm' });
 * `Call the API with ${raw}`;
 * ```
 *
 * Every existing control has already run by then and passed. `reveal()` did
 * what it was asked, the audit hook fired if a context was set, and the result
 * is a `string` like any other. A prompt does not leak because a value ended
 * up somewhere it was not meant to go; it leaks because a developer put it
 * there on purpose and was right to need it. The question a policy can answer
 * is not "did this escape" but "may this class go to a third party at all",
 * and that question has to be asked somewhere.
 */

/** Raised when a class's policy does not permit an external sink. */
export class ExternalSendNotAllowedError extends Error {
  readonly klass: SensitivityClass;
  readonly label: string | undefined;
  readonly sink: string;

  constructor(klass: SensitivityClass, label: string | undefined, sink: string) {
    super(
      `sendToExternal: sensitivity class '${klass}'${label === undefined ? '' : ` (label '${label}')`} ` +
        `may not be sent to external sink '${sink}'. Set advisory.allowSendToExternal to true on ` +
        `the '${klass}' policy with registerPolicy() to permit it; any other value, including ` +
        'undefined, is a refusal.'
    );
    this.name = 'ExternalSendNotAllowedError';
    this.klass = klass;
    this.label = label;
    this.sink = sink;
  }
}

/** Raised when the value about to be sent is a redaction marker rather than a value. */
export class RedactedMarkerError extends Error {
  readonly klass: SensitivityClass;
  readonly sink: string;

  constructor(klass: SensitivityClass, sink: string) {
    super(
      `sendToExternal: the revealed value carries a redaction marker, so it has already been ` +
        `scrubbed upstream and sending it to '${sink}' would send the placeholder. ` +
        'A model accepts a marker and answers as though the value were real.'
    );
    this.name = 'RedactedMarkerError';
    this.klass = klass;
    this.sink = sink;
  }
}

/**
 * A redaction marker in a string.
 *
 * Anchored to the two shapes this library produces by default. A custom policy
 * can emit any string it likes, so this recognizes the defaults rather than
 * proving absence. Not global: a global `RegExp` carries `lastIndex` between
 * calls, and a shared one on a refusal path would answer differently on every
 * second call.
 */
const MARKER = /\[REDACTED(?::[^\]\s]{1,64})?\]/;

/**
 * Authorize and perform a reveal destined for a third party.
 *
 * The only export in this package that returns a raw string, and a test
 * enumerates the module's exports to keep it that way.
 *
 * The ordering matters and is worth reading before changing:
 *
 * 1. Resolve the policy for the value's class. An absent policy is an error,
 *    not a default.
 * 2. Check `advisory.allowSendToExternal`. Anything other than `true` throws,
 *    `undefined` included. On a stock installation both classes are `false`,
 *    so a first call fails and the error names the field to change. That is a
 *    bad first-run experience and the only defensible reading of a flag whose
 *    meaning is "this data may leave for a third party": the other reading
 *    makes the library's first enforcement point default to permitting the
 *    thing it exists to control.
 * 3. Reveal through the ordinary gate, so TTL, revocation, reveal counting,
 *    environment restrictions and the audit hook all run. This function does
 *    not read the private field and has no path to it; it calls `reveal()`
 *    like any other caller.
 * 4. Refuse a revealed form carrying a redaction marker. Every other
 *    integration that ships a marker sends a broken value to something that
 *    rejects it: a `[REDACTED:credential]` bearer token gets a 401. A model
 *    accepts it, answers as if the value were real, and the failure surfaces
 *    later as a wrong answer rather than as an error, with the placeholder now
 *    in the conversation history.
 *
 * Step 3 is what makes this worth building rather than documenting. The
 * context it constructs always carries a sink name, so an audit sink can
 * answer "what left for a third party today" without the application having
 * remembered to name its contexts well, which in practice it does not.
 *
 * The context is a child of whatever is ambient, so an `auditReveal` installed
 * by `withRevealContext` still fires. Passing a bare context would replace the
 * ambient one and silence exactly the hook that most wants to see this call.
 *
 * A prompt built with core's `st` tag is itself a `SensitiveString`, and it
 * combines classes by precedence, so a credential anywhere in the prompt makes
 * the whole prompt a credential and step 2 sees the most restrictive class
 * rather than the least. A caller cannot dilute a credential by surrounding it
 * with harmless text.
 *
 * @param value - The value, or a whole `st`-built prompt
 * @param options - The sink, the required reason, and any extra audit tags
 * @returns The raw string
 *
 * @throws TypeError If the value is not a `SensitiveString`, or the sink name
 *         or reason is not a non-empty string.
 * @throws ExternalSendNotAllowedError If the class's policy does not permit it.
 * @throws RedactedMarkerError If the revealed form carries a redaction marker.
 *
 * @example
 * ```ts
 * const prompt = st`Summarize the recent activity for ${customerEmail}.`;
 *
 * const body = {
 *   model,
 *   messages: [{
 *     role: 'user',
 *     content: sendToExternal(prompt, {
 *       sink: { name: 'anthropic', detail: model },
 *       reason: 'account summary for support agent',
 *     }),
 *   }],
 * };
 * ```
 */
export function sendToExternal(
  value: SensitiveString<SensitivityClass>,
  options: SendToExternalOptions
): string {
  if (!(value instanceof SensitiveString)) {
    throw new TypeError('sendToExternal: value must be a SensitiveString');
  }

  const sink = options?.sink;

  if (typeof sink?.name !== 'string' || sink.name.trim() === '') {
    throw new TypeError('sendToExternal: options.sink.name must be a non-empty string');
  }

  if (typeof options.reason !== 'string' || options.reason.trim() === '') {
    throw new TypeError(
      'sendToExternal: options.reason must be a non-empty string explaining why this value is ' +
        'going to this sink'
    );
  }

  // Throws when no policy is registered for the class, which is the correct
  // answer: an unregistered class has said nothing about external sinks, and
  // the absence of a statement is not a permission.
  const policy = getPolicy(value.klass);

  if (policy.advisory?.allowSendToExternal !== true) {
    throw new ExternalSendNotAllowedError(value.klass, value.label, sink.name);
  }

  const raw = value.reveal(
    createChildContext({
      // The prefix is what lets an audit sink filter on egress without the
      // application having named its contexts well. It is a convention this
      // package applies rather than a `core` change, because `RevealContext`
      // has no sink field and adding one for this caller is not obviously
      // right for the others.
      name: `external:${sink.name}`,
      reason: options.reason,
      tags: {
        ...options.tags,
        sink: sink.name,
        ...(sink.detail === undefined ? {} : { sinkDetail: sink.detail }),
      },
    })
  );

  if (MARKER.test(raw)) {
    throw new RedactedMarkerError(value.klass, sink.name);
  }

  return raw;
}

/** Whether a string carries one of this library's default redaction markers. */
export function hasRedactionMarker(value: string): boolean {
  return MARKER.test(value);
}
