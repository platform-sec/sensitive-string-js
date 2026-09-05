# @platform-sec/sensitive-string-llm

Sending data to a language model, with the one decision the rest of this library cannot make for you
written down in a policy instead of at a call site.

## What the leak actually is

Not a value someone forgot to wrap. Interpolation into an ordinary template literal is already safe:

```ts
const key = new SensitiveString('LEAKED_SECRET_abc123xyz', 'credential', 'api_key');

`Use key ${key} now`; // "Use key [REDACTED:credential] now"
```

Nobody writes that. The real code is this, and until now there was no gate on it:

```ts
const raw = key.reveal({ name: 'llm' });

`Call the API with ${raw}`; // contains the secret
```

Every existing control has already run by then and passed. `reveal()` did what it was asked, the
audit hook fired if a context was set, and the result is a `string` like any other. Logging and
serialization leak because a value ended up somewhere it was not meant to go. A prompt leaks because
a developer put the value there on purpose, decided it was needed for the task, and was right.

The question a policy can answer is not "did this escape" but "may this class go to a third party at
all". `advisory.allowSendToExternal` has been declared on `SensitivityAdvisory` since the beginning
and read by nothing. This package is the first thing that reads it.

## Installation

```bash
pnpm add @platform-sec/sensitive-string-llm
```

## Requirements

- Node.js 22.12+
- `@platform-sec/sensitive-string-core` and `@platform-sec/sensitive-string-scrub` (peer
  dependencies)

Both are peers rather than regular dependencies. Structural redaction is `instanceof` checks, and
two copies of core in `node_modules` make every one of them miss.

This package has no third-party runtime dependencies. It ships no provider SDK, does not wrap
`fetch`, does not hold an API key, and never makes a request. It hands you a payload and a decision.

## The honest sentence

Read this before the API.

> `scrubForPrompt` protects values this library is holding and values sitting under a key with a
> credential-shaped name. It does not read your prose. If you paste a customer record into a system
> prompt, this package sends it.

That is the whole limitation, stated up front, because the alternative is a caller who installs a
scrubber and stops reading their prompts. See [What this does not do](#what-this-does-not-do).

## Quick start

```ts
import { st } from '@platform-sec/sensitive-string-core';
import { createPromptScrubber, sendToExternal } from '@platform-sec/sensitive-string-llm';

// Once, at setup. The factory resolves the policy and the content paths.
const scrub = createPromptScrubber();

// A prompt built with the tag is itself a wrapped value: it redacts if it is
// logged, and stringifying it by accident produces a marker rather than bytes.
const prompt = st`Summarize the recent activity for ${customerEmail}.`;

const { prompt: body, removed } = scrub({
  model,
  messages: [
    {
      role: 'user',
      // The one call that turns a wrapped value into bytes.
      content: sendToExternal(prompt, {
        sink: { name: 'anthropic', detail: model },
        reason: 'account summary for support agent',
      }),
    },
  ],
});

await client.messages.create(body);
```

**On a stock installation that example throws**, because `sensitive` does not permit an external sink
until a policy says so. That is the feature working, it is the first thing you will hit, and the
error message names the class and the field. The fix is one call:

```ts
import { getPolicy, registerPolicy } from '@platform-sec/sensitive-string-core';

const policy = getPolicy('sensitive');

registerPolicy(
  { ...policy, advisory: { ...policy.advisory, allowSendToExternal: true } },
  { overwrite: true }
);
```

Write that once, in a place that shows up in review. That is the whole point of the feature: the
decision lives in a policy rather than at whichever call site needed it that afternoon.

## `sendToExternal`

The only export in this package that returns a raw string, and a test enumerates the module's
exports to keep it that way.

```ts
sendToExternal(value, { sink: { name, detail }, reason, tags }): string
```

In order:

1. Resolve the policy for the value's class. An absent policy is an error, not a default.
2. Check `advisory.allowSendToExternal`. Anything other than `true` throws
   `ExternalSendNotAllowedError`. **`undefined` throws.** `false` throws.
3. Reveal through the ordinary gate, so TTL, revocation, reveal counting, environment restrictions
   and the audit hook all run.
4. Refuse a revealed form carrying a redaction marker.

### Why `undefined` is a refusal

The flag was declared and set by neither default policy, so it read `undefined` on every value in a
stock installation and the two obvious ways to test it, `if (flag)` and `if (flag !== false)`,
disagreed on all of them. `core` now writes `false` explicitly on both `sensitive` and `credential`,
which is behaviourally identical under this rule and reads completely differently to anyone reviewing
a policy: an absent field looks like an oversight.

`sensitive` starts closed rather than permissive because the class is deliberately coarse and covers
a customer email as readily as an internal note.

### The audit record

The context this builds is a child of whatever is ambient, so an `auditReveal` installed by
`withRevealContext` still fires. It carries:

```
name  "external:anthropic"
tags  { sink: 'anthropic', sinkDetail: 'claude-opus-5', ...yours }
```

The `external:` prefix is what lets an audit sink answer "what left for a third party today" without
the application having remembered to name its contexts well, which in practice it does not.

`reason` is required here and optional on `RevealContext`. This is the one call in the library whose
purpose is to authorize an irreversible disclosure outside the trust boundary, and a required string
is the cheapest forcing function for a moment of thought at the call site.

### The marker rule, in its strictest form

Every other integration that ships a `[REDACTED:` marker sends a broken value to a system that will
reject it: a redacted bearer token gets a 401. A model accepts the marker and continues. It answers
as though the value were real, the failure surfaces later as a wrong answer rather than as an error,
and the placeholder is now in the conversation history. So `sendToExternal` refuses.

`scrubForPrompt` counts markers in the *input* rather than throwing on them, because at that point
nothing has been sent and you may be about to fix it. `removed.markersSeen` is the number.

### Class combination is free

Add a credential to an `st`-built prompt and the whole prompt becomes a credential, because the tag
combines by precedence. So the check in step 2 sees the most restrictive class anywhere in the prompt
rather than the least, and you cannot dilute a credential by surrounding it with harmless text.

## `scrubForPrompt`

```ts
const { prompt, removed } = scrubForPrompt(payload, options);
const scrub = createPromptScrubber(options); // the form for a request path
```

`scrubForPrompt` resolves the policy on every call, which is right for a script and wrong for a
server. Resolution walks and lowercases every denied key and path; the factory is where that goes.

### The three positions a value can occupy

Everything this does follows from sorting a request body into three positions, because only one of
them has a good defence.

| Position | Example | Covered |
|---|---|---|
| 1. Structured, wrapped | a `SensitiveString` or a `serialize()` result at a key | Yes, and the coverage is real |
| 2. Structured, unwrapped | a plain string at `api_key`, `authorization` | To the extent the key has a credential-shaped name |
| 3. Prose | `messages[].content`, a system prompt, a retrieved document | **No** |

Position 3 is where a leak actually happens in a retrieval-augmented application, and it is where
nothing in this library helps. The key is `content`. The key is always `content`. It carries no
information about what is inside it, and the thing inside it is the reason the request exists, so
denying the key denies the request.

The package's own test suite asserts a canary is **present** after scrubbing a prose position. A test
that documents a known gap is worth more than a gap nobody wrote down.

### The seam for a classifier you already run

```ts
const scrub = createPromptScrubber({
  transformContent: (text, path) => yourDlpService.redact(text),
});
```

Whatever the hook returns is trusted verbatim. It is not called on a marker structural redaction just
wrote, because a hook that rewrote a marker into something value-shaped is the one failure this
package is strictest about.

### The manifest

`removed` is a `scrub` `ScrubReport` plus two fields. It carries classes, key names and counts, and
never a value:

```ts
{
  instances: 1,
  classes: Set { 'credential' },
  deniedKeys: [ 'api_key' ],
  markersSeen: 0,
  handles: [ '<<customer:8129b4f50be1>>' ],
  contentPositions: 3,
  failed: false,
}
```

`contentPositions: 0` means the body matched none of the shipped content paths, which is
indistinguishable from having upgraded an SDK into a new schema. It is the one signal you get for
that. Supply your own `contentPaths` when it happens.

### Read `instances` before you send

This one matters, and it is the mirror image of the marker rule above.

`instances > 0` means the body carried a wrapped value that did **not** go through
`sendToExternal`, and structural redaction has replaced it with `[REDACTED:credential]` where it
stood. That is safe, in the sense that nothing leaked. It is not correct: the body you are holding
now has a placeholder where a value belonged, and a model accepts a placeholder and answers as
though it were real. You get a confident wrong answer instead of an error, and the placeholder is
now in the conversation history for turn two.

So treat it as a bug in the caller, not as the scrubber doing its job:

```ts
const { prompt: body, removed } = scrub(payload);

if (removed.instances > 0) {
  throw new Error(
    `${removed.instances} wrapped value(s) reached the request body without sendToExternal`
  );
}
```

The scrubber cannot make that call for you. A marker in an outbound body is unambiguously wrong for
a model and unambiguously right for a log line, and this package is handed a body that may be about
to become either. What it can do is count them, which is what `instances` and `classes` are.

### Failure is fail closed

`scrubForPrompt` **throws**. It does not use `scrub`'s `guardedScrub`, and the difference is
deliberate: an error tracker's stub preserves the signal that an error occurred while dropping the
payload, and a prompt has no equivalent. A stub prompt is a request that costs money and returns an
answer to a question nobody asked, and the caller cannot tell it from a real one.

The thrown `PromptScrubFailedError` names the stage, the path and the exception type, and carries
nothing else: no message, no stack from the original, and no `cause`. This is the package that fails
while holding the values, so its own error is a leak position.

`onScrub` still fires with `failed: true` before the throw. An operator needs to see a scrubber
failing on every request of one shape, and a thrown error the caller catches and retries is not that
signal.

## Entity handles

A stable, keyed pseudonym, so a model can be told "the customer" and carry that reference across
turns without receiving the customer.

```ts
import { createHandleMap, entityHandle, rehydrate } from '@platform-sec/sensitive-string-llm';

const map = createHandleMap(); // per request. Never cached.

const handle = entityHandle(customerEmail, {
  key: HANDLE_KEY,       // at least 16 bytes. 32 from randomBytes is the recommendation.
  scope: conversationId, // see below
  record: map,
});

// handle === '<<customer_email:8129b4f50be1>>'
```

Derivation is `HMAC-SHA256(key, scope || 0x00 || klass || 0x00 || value)`, hex, truncated to 12
characters by default. Keyed, never a plain hash, and there is no unkeyed mode: the values that get
handles are low-entropy by definition, an email address under an unkeyed SHA-256 is recoverable from
a wordlist in seconds, and the premise of a handle is that it appears outside the trust boundary,
which is exactly where an offline attack happens.

12 hex characters is 48 bits, where a one-in-a-million collision arrives at roughly 24,000 distinct
entities under one key and scope. `length: 16` is available. 8 is not: at 32 bits a
one-in-a-thousand collision arrives at about 3,000 entities, which a support-ticket workload reaches
in a week, and a collision means two customers become one customer in the model's view.

### Credentials never get one

`entityHandle` throws on a `credential`. A handle is useful when a model needs to refer to something
repeatedly and does not need its contents: a customer, an account, a case number. That does not
describe an API key. A model that needs a key needs the key, and a model that does not need the key
should not be told a key exists.

The refusal is hard-coded, not read from a policy flag, and a test asserts it stays that way even
when `credential`'s policy is opened all the way up.

### Rehydration is a substitution oracle

This is the dangerous half, and the reason rehydration is opt-in per call.

A handle is only useful if something maps it back, and the natural place is the response: the model
says "email `<<E:a1b2c3d4e5f6>>` about the refund" and you substitute the address before handing the
instruction to a mailer. **That substitution step is a function that takes text an attacker can
influence and returns secrets.** No exotic threat model is needed: a model can be steered by any
document in its context, in a retrieval-augmented application that is a document some user uploaded,
and a response frequently contains verbatim spans from that context. Forging a handle costs nothing;
it is a syntactic pattern.

Four mitigations, in the order they matter:

1. **Resolution is against a map the current call was handed.** No package-level registry, no global
   lookup. A handle this request did not mint resolves to nothing.
2. **The result is a `SensitiveString`, not a raw string**, because a forged token can copy a real one
   out of the prompt, and the prompt sits next to the document in the context. Whatever consumes the
   result goes through the same gate as everything else, so the authorization is the consumer's
   rather than the model's.
3. **Opt-in per call**, never inside `scrubForPrompt`, holding nothing after it returns.
4. **`credential` never participates**, so the worst case is a pseudonym resolving to a value you
   already had.

```ts
const { text, unresolved } = rehydrate(response, { map });

if (unresolved.length > 0) {
  // Handle-shaped tokens the model was never given. Worth an alert.
}

await mailer.send(text); // a SensitiveString: the mailer authorizes the reveal
```

`rehydrate` takes a `string`, not a stream, and the signature is the enforcement. A handle can span
two chunks of a streamed response; anything matching per chunk misses a split handle and matches
once you buffer, which is a correctness problem with a security failure mode. Rehydrate assembled
text.

### The reverse map is a plaintext store

It is a new place raw values accumulate, in a package whose purpose is to reduce those. Three rules:

- **You create it, per request, and pass it in.** This package holds no module-level state.
- **It holds `SensitiveString` instances**, so its contents redact if it is logged and the values keep
  their TTL, revocation and reveal counters. A map that outlives a value's lifetime hands back an
  instance that refuses, which is correct and free.
- **Its lifetime is the request.** A cached map turns handles into a cross-user correlation key, and
  two users whose values collide under truncation get each other's.

### What a handle does not hide

A handle is a pseudonym, not anonymization. Stability is the feature, and a stable token is a
correlation key: whoever holds the conversation logs can count how often the same entity appears,
which entities co-occur, and what was said about each. Under one key and scope that holds across
every conversation you ever send.

`scope` is the control. Scope per conversation unless cross-conversation stability is specifically
needed; it costs nothing and turns the correlation window from "forever" into "this thread".

A handle also discloses that an entity of that kind existed, and the prefix says which kind. That is
the point, and it is still disclosure.

## Provider shapes

`contentPaths` decides which dotted paths hold prose. The package attaches at the payload rather
than at the client, so it works for any provider whose request is a JSON object, and the only
per-provider knowledge is a list of paths.

```ts
import { CONTENT_PATH_SHAPES } from '@platform-sec/sensitive-string-llm';

createPromptScrubber({ contentPaths: CONTENT_PATH_SHAPES.anthropicMessages.paths });
```

**None of the shipped paths has been measured against an installed SDK.** No provider SDK is a
dependency of this package, not even a dev one, and a fixture written from a document tests the
document rather than the provider. Each shape carries `verified: false` and the schema it was
written from, rather than a version number that would be dishonest to print. Treat them as a
starting point and supply your own for anything else.

This affects where your `transformContent` hook runs and where handles are counted. It does not
affect what the package protects: structural redaction and the key denylist run over the whole
payload regardless, and that is the half of the leak this package actually closes.

## Tool results are inbound

A tool result is content your application produced and is about to send to the model, so it lands in
position 3 by default with one difference from a retrieved document: you know where it came from. A
tool that reads a secrets manager returns a `SensitiveString`, so a tool result assembled without
stringifying it stays in position 1 and is covered.

Assemble tool result blocks as structures and let them be scrubbed as structures. `JSON.stringify`
on the way into one is the same mistake as `JSON.stringify` on the way into a log line: it flattens
the value to a marker, and a marker is the one thing that must not reach a model.

## What this does not do

- **No content classification.** No regex sweep over `content` for card numbers, addresses or key
  prefixes. Three reasons, of which the first is sufficient: a sweep that misses is worse than no
  sweep, because the failure mode of a partial classifier is not "some leaks get through" but "the
  reviewer stops looking". The library also has no scanner (`core.patterns` has one entry, anchored
  at both ends, which answers "is this whole string an address" rather than "is there one in this
  paragraph"). And DLP classification is a mature, separately licensed category. Run yours and hand
  the result to `transformContent`.
- **No provider client.** No `fetch` wrapper, no API key, no request. Use
  `@platform-sec/sensitive-string-http` and its client wrappers for the wire; the ordering is
  `sendToExternal` first, then the client.
- **No prompt injection defence.** A model that has been talked into asking for a credential and a
  model that legitimately needs one look identical from here. What this can do is make sure the
  answer to "may this class go to an external sink" was decided in a policy rather than at the call
  site.
- **No output filtering.** Scanning a response for leaked training data is a different feature with a
  different failure mode. The one thing this looks for in a response is a handle it minted.
- **No token accounting.** Handle length and tokenizer behaviour affect cost and are yours.
- **No caching or logging of prompts.** The reverse map exists only when you build one, only for as
  long as you hold it.

## API

| Export | What it is |
|---|---|
| `sendToExternal` | The authorization gate. The only export returning a raw string. |
| `createPromptScrubber` / `scrubForPrompt` | Structural scrub plus the manifest. |
| `entityHandle` / `createHandleMap` | Keyed pseudonyms and the per-request reverse map. |
| `rehydrate` | Substitute minted handles back, into a wrapped value. |
| `handlePattern` / `hasRedactionMarker` | The two recognizers, for callers writing their own checks. |
| `CONTENT_PATH_SHAPES` and friends | Per-provider content paths, unverified, with their provenance. |
| `ExternalSendNotAllowedError`, `RedactedMarkerError`, `HandleNotAllowedError`, `PromptScrubFailedError` | The four refusals. |

## License

MIT
