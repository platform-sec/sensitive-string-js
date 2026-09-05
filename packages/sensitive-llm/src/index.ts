/**
 * @platform-sec/sensitive-string-llm
 *
 * Sending data to a language model, with the one decision the rest of this
 * library cannot make for you written down in a policy instead of at a call
 * site.
 *
 * Logging and serialization leak because a value ended up somewhere it was not
 * meant to go. A prompt leaks because a developer put the value there on
 * purpose, decided it was needed for the task, and was right. Every existing
 * control has already run and passed by the time the value reaches the string:
 *
 * ```ts
 * const raw = key.reveal({ name: 'llm' });
 * `Call the API with ${raw}`;             // contains the secret, and nothing objected
 * ```
 *
 * Three exports, and they do not carry equal weight.
 *
 * - `sendToExternal` is the feature. It turns `advisory.allowSendToExternal`
 *   from a declared field nothing read into an enforced one, audits the reveal
 *   with the sink's name in it, and refuses a value that is already a
 *   redaction marker. On a stock installation it refuses everything, and the
 *   error names the policy field to change.
 * - `scrubForPrompt` is worth having and closes the smaller half of the leak.
 *   A wrapped value in a request body is already safe; the leak is the
 *   unwrapped prose beside it, and a walk over a keyed structure does not
 *   reach prose.
 * - `entityHandle` mints a keyed, stable pseudonym so a model can refer to
 *   "the customer" across turns without receiving the customer. Never for a
 *   credential, and rehydration resolves only against a map the calling
 *   request built and hands back wrapped values.
 *
 * What this package does not do: classify content, wrap a network client, hold
 * an API key, defend against prompt injection, filter model output, or keep
 * any module-level state.
 *
 * @example
 * ```ts
 * import { st } from '@platform-sec/sensitive-string-core';
 * import { createPromptScrubber, sendToExternal } from '@platform-sec/sensitive-string-llm';
 *
 * const scrub = createPromptScrubber();
 *
 * const prompt = st`Summarize the recent activity for ${customerEmail}.`;
 *
 * const { prompt: body } = scrub({
 *   model,
 *   messages: [{
 *     role: 'user',
 *     content: sendToExternal(prompt, {
 *       sink: { name: 'anthropic', detail: model },
 *       reason: 'account summary for support agent',
 *     }),
 *   }],
 * });
 * ```
 *
 * @packageDocumentation
 */

export type {
  ExternalSink,
  SendToExternalOptions,
  EntityHandleOptions,
  HandleMap,
  PromptManifest,
  PromptScrubOptions,
  PromptScrubResult,
  PromptScrubber,
  RehydrateOptions,
  RehydrateResult,
} from './types.js';

export {
  ExternalSendNotAllowedError,
  RedactedMarkerError,
  hasRedactionMarker,
  sendToExternal,
} from './external.js';

export { HandleNotAllowedError, createHandleMap, entityHandle, handlePattern } from './handle.js';

export { rehydrate } from './rehydrate.js';

export { PromptScrubFailedError, createPromptScrubber, scrubForPrompt } from './scrub.js';

export {
  ANTHROPIC_MESSAGES,
  CONTENT_PATH_SHAPES,
  DEFAULT_CONTENT_PATHS,
  LLM_DENY_KEYS,
  OPENAI_CHAT_COMPLETIONS,
  OPENAI_RESPONSES,
} from './shapes.js';
export type { ContentPathShape } from './shapes.js';
