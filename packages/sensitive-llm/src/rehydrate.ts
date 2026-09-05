import {
  sensitiveTemplate,
  type SensitiveString,
  type SensitivityClass,
} from '@platform-sec/sensitive-string-core';

import { handlePattern } from './handle.js';
import type { RehydrateOptions, RehydrateResult } from './types.js';

/**
 * Turning a model's handles back into values.
 *
 * This is the dangerous half of pseudonymization and the half the roadmap
 * sentence does not mention. A handle is only useful if something maps it
 * back, and the natural place is the response: the model says "email
 * `<<E:a1b2c3d4>>` about the refund" and the application substitutes the
 * address before handing the instruction to a mailer. That substitution step
 * is a function that takes text an attacker can influence and returns secrets.
 *
 * The text is attacker-influenceable in two ordinary ways that need no exotic
 * threat model. A model can be steered by any document in its context, which
 * in a retrieval-augmented application is a document some user uploaded. And a
 * response frequently contains verbatim spans from that context. So a document
 * containing a handle-shaped token gets echoed, a naive extractor matches it,
 * and a value comes out.
 *
 * Four mitigations, in the order they matter:
 *
 * 1. Resolution is against a map the current call was handed, built from the
 *    handles that call minted. There is no package-level registry and no
 *    global lookup, so a forged `<<E:deadbeef01ff>>` is simply not in the map.
 * 2. The map is not enough on its own, because a forged token can copy a real
 *    one out of the prompt, and the prompt sits next to the document in the
 *    context. So the result is a `SensitiveString`, not a raw string, and
 *    whatever consumes it goes through the same gate as everything else. If a
 *    rehydrated address is about to be emailed, that email client's
 *    integration is what authorizes it, and the authorization is not "a model
 *    said so".
 * 3. Rehydration is opt-in per call, never happens inside `scrubForPrompt`,
 *    and holds nothing after it returns.
 * 4. `credential` never participates, so the worst case of the oracle is a
 *    pseudonym resolving to a value the caller already had.
 *
 * ## Streaming
 *
 * A streamed response arrives in fragments and a handle can span two of them.
 * Anything running per chunk fails to match a split handle and matches once
 * the caller buffers, which is a correctness problem with a security failure
 * mode. So this takes a `string` rather than a stream, and the type signature
 * is the enforcement: rehydrate assembled text.
 *
 * ## Substitution mechanics
 *
 * Substitution is by splitting and reassembly through core's template tag, not
 * by `replace`. `String.prototype.replaceAll` with a *string* replacement
 * interprets `$` patterns in the replacement even when the pattern itself is a
 * plain string. Measured on Node 22.15.0:
 *
 * ```
 * const s = 'a <<E:a1b2c3d4e5f6>> b';
 *
 * s.replaceAll(handle, 'pa$$&word')       ->  'a pa$&word b'
 * s.replaceAll(handle, "x$'y")            ->  'a x by b'
 * s.replaceAll(handle, 'x$`y')            ->  'a xa y b'
 * s.replaceAll(handle, () => 'pa$$&word') ->  'a pa$$&word b'
 * ```
 *
 * The first corrupts a value containing `$$`. The second and third splice the
 * text that followed or preceded the match into the substituted result, which
 * is how surrounding prompt text ends up inside what the caller believes is a
 * bare value. None of them throws and all produce a plausible-looking string.
 * The fourth is the function form, which is literal, and splitting is stronger
 * still: it has no replacement string at all, so there is nothing to
 * interpret.
 */

/**
 * Substitute the handles a call minted back into a model's response.
 *
 * Reveals each substituted value through the ordinary gate, by way of core's
 * template tag, so TTL, revocation, reveal counting and the audit hook all run
 * and the result retains every source value's state. A map holding an expired
 * value therefore makes this throw rather than hand back a raw string, which
 * is the refusing instance behaving correctly.
 *
 * @param text - The assembled response text
 * @param options - The per-request map, and an optional label for the result
 * @returns The wrapped substituted text, plus which tokens resolved and which
 *          did not
 *
 * @throws TypeError If `text` is not a string or `options.map` is not a `Map`.
 * @throws Error Whatever the gate throws for a value that has expired, been
 *         revoked, or exhausted its reveal budget.
 *
 * @example
 * ```ts
 * const { text, unresolved } = rehydrate(response, { map });
 *
 * if (unresolved.length > 0) {
 *   alert('handle-shaped tokens the model was never given', { count: unresolved.length });
 * }
 *
 * await mailer.send(text); // a SensitiveString: the mailer authorizes the reveal
 * ```
 */
export function rehydrate(text: string, options: RehydrateOptions): RehydrateResult {
  if (typeof text !== 'string') {
    throw new TypeError('rehydrate: text must be a string. Rehydrate assembled text, not a chunk.');
  }

  const map = options?.map;

  if (!(map instanceof Map)) {
    throw new TypeError('rehydrate: options.map must be the Map this request built');
  }

  const parts: string[] = [];
  const values: SensitiveString<SensitivityClass>[] = [];
  const resolved: string[] = [];
  const unresolved: string[] = [];

  const pattern = handlePattern();
  let literal = '';
  let cursor = 0;
  let match = pattern.exec(text);

  while (match !== null) {
    const token = match[0];
    const value = map.get(token);

    literal += text.slice(cursor, match.index);
    cursor = match.index + token.length;

    if (value === undefined) {
      // Left in place verbatim. Removing it would hide from the caller that
      // something in the response was shaped like a handle, and replacing it
      // with a marker would put this library's own marker into text bound for
      // a second turn.
      literal += token;

      if (!unresolved.includes(token)) {
        unresolved.push(token);
      }
    } else {
      parts.push(literal);
      literal = '';
      values.push(value);

      if (!resolved.includes(token)) {
        resolved.push(token);
      }
    }

    match = pattern.exec(text);
  }

  parts.push(literal + text.slice(cursor));

  return {
    text: assemble(parts, values, options.label),
    resolved,
    unresolved,
  };
}

/**
 * Build the wrapped result out of the literal parts and the resolved values.
 *
 * Through core's tag rather than by concatenating revealed strings, so the
 * reveals are audited, the result is a derived instance retaining every
 * source's TTL and revocation state, and the class is combined by precedence
 * rather than asserted here.
 */
function assemble(
  parts: readonly string[],
  values: readonly SensitiveString<SensitivityClass>[],
  label: string | undefined
): SensitiveString<SensitivityClass> {
  // A tagged template hands its tag an array carrying `raw`, and core's direct
  // form accepts exactly that shape. Building one is what lets the assembly
  // reuse the audited path instead of growing a second one.
  const copy = [...parts];
  const strings = Object.assign(copy, { raw: copy }) as unknown as TemplateStringsArray;

  const tag = sensitiveTemplate(label === undefined ? {} : { label });

  return tag(strings, ...values);
}
