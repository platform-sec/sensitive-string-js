# @platform-sec/sensitive-string-testing

Test secrets, leak assertions, matchers, and audit mocks for
[`@platform-sec/sensitive-string-core`](../sensitive-core).

The core promise of `SensitiveString` is that a sensitive value does not reach
output it was never meant to reach. That promise has to be tested, and every
project that tests it ends up writing the same three things: a canary value, a
check that the canary is absent, and a fake audit context. This package is those
three things, written once.

## Installation

```bash
pnpm add -D @platform-sec/sensitive-string-testing
```

`@platform-sec/sensitive-string-core` is a peer dependency. No test framework is:
the matchers are a plain object you hand to `expect.extend`, and anything that
needs a spy takes `vi.fn` or `jest.fn` as an argument.

## Requirements

- Node.js 22.12+
- Vitest or Jest, or any runner whose `expect` has `extend`

## Test secrets

```typescript
import { createTestSecret } from '@platform-sec/sensitive-string-testing';

const apiKey = createTestSecret('credential', 'api_key');
// __CANARY_1767225600000_1_3f9c1ab4e207__
```

The value is unique per call and conspicuous on purpose: when it turns up in a
log capture or a snapshot diff, there is no question about what it is or which
test produced it. Uniqueness comes from a counter, the clock, and
`node:crypto`, so it survives both fake timers and a stubbed `Math.random`.

`createTestSecret` takes everything `SensitiveStringOptions` takes, so a test
that needs an expiring secret or an `onExpire` hook passes those straight
through:

```typescript
const otp = createTestSecret('credential', 'otp', { ttl: 30_000 });
const email = createTestSecret('sensitive', 'email', { value: 'jane@example.com' });
```

Two shapes are common enough to have their own factory:

```typescript
import { createExpiredSecret, createExpiringSecret } from '@platform-sec/sensitive-string-testing';

createExpiredSecret('credential', 'otp');            // already past its deadline
createExpiringSecret('credential', 'session', 60_000); // expires in a minute
```

`createExpiredSecret` needs no fake timers: `ttl: 0` puts the deadline at
construction.

## Leak assertions

```typescript
import { createTestSecret, expectNotLeaked } from '@platform-sec/sensitive-string-testing';

it('does not leak the key into the response', async () => {
  const apiKey = createTestSecret('credential', 'api_key');

  const response = await handler(apiKey);

  expectNotLeaked(apiKey, response, logger.entries, await response.text());
});
```

`expectNotLeaked` walks each target rather than serializing it. `JSON.stringify`
asks an object what it wants to show, and what an object wants to show is
exactly the wrong question for a leak check: a `toJSON` that omits a field hides
a raw copy that is still sitting on the object, and a `SensitiveString` renders
as its redacted form whether or not a plain copy sits next to it.

The walk reaches strings, other primitives, arrays and the properties attached
to them, `Map` and `Set` contents, typed arrays and `Buffer` contents, `RegExp`
sources, object keys, values behind getters, and own properties whether or not
they are enumerable, which is how an `Error`'s `message` and `stack` and a
`match()` result's `input` are covered. It does not reach closure variables,
`WeakMap` contents, unsettled promises, or function bodies.

There is no depth limit. The walk uses an explicit stack, so a leak thousands of
levels down is still found; a limit would report it as no leak at all. Getters
are invoked, which is worth knowing if a getter in your fixture has side
effects.

A value still wrapped in a `SensitiveString` is not a leak and is not reported
as one.

When a value does leak, the failure names the class, the label, and the path it
was found at, and quotes the surrounding text with the value replaced:

```
LeakageDetectedError: Sensitive value leaked.
  Label:   api_key
  Class:   credential
  Target:  [0].headers["authorization"]
  Context: Bearer [LEAKED VALUE]
  The value itself is withheld so this message is safe to log.
```

A leak assertion that proves a secret leaked by printing the secret has only
moved the leak, so it prints the location instead.

### Redaction assertions

```typescript
import { expectRedacted } from '@platform-sec/sensitive-string-testing';

expectRedacted(formatUserLog({ email }), email);
```

`expectRedacted` checks two things: the raw value is absent, and the rendering
the class policy actually produces is present. It reads that rendering from the
instance rather than assuming `[REDACTED:class]`, so a custom policy passes
without the test having to know its format, and a policy that stops redacting
fails. Pass `customPattern` when the output transforms the rendering.

Both assertions search for the complete value, so a policy that discloses only
part of one reads as a successful redaction. Partial disclosure is what `mask()`
and its `minMasked` floor govern in core, and `registerPolicy` already rejects a
redaction that embeds the value.

## Matchers

```typescript
// vitest.setup.ts
import { expect } from 'vitest';
import { setupSensitiveMatchers } from '@platform-sec/sensitive-string-testing';

setupSensitiveMatchers(expect);
```

```typescript
expect(token).toBeSensitiveString();
expect(token).toHaveSensitivityClass('credential');
expect(token).toHaveLabel('api_token');
expect(token).toRevealAs('abc123');
expect(otp).toBeExpired();
expect(response).not.toContainSensitive(token);
```

Both frameworks expose a registered matcher asymmetrically as well, so this
works with no further setup:

```typescript
expect(response).toEqual({
  token: expect.toBeSensitiveString(),
  status: 'ok',
});
```

`toRevealAs` goes through `reveal()`, so an expired value or a policy denial
fails the assertion instead of passing on a remembered copy. When it fails it
reports the redacted rendering and the length rather than the value.

### Types

With Vitest, import the ready-made augmentation once:

```typescript
import '@platform-sec/sensitive-string-testing/vitest';
```

With Jest, or to write it yourself, extend from the exported interface:

```typescript
import type { SensitiveMatchers } from '@platform-sec/sensitive-string-testing';

declare global {
  namespace jest {
    interface Matchers<R> extends SensitiveMatchers<R> {}
  }
}
```

## Snapshot serializer

```typescript
// vitest.setup.ts
import { expect } from 'vitest';
import { sensitiveSerializer } from '@platform-sec/sensitive-string-testing';

expect.addSnapshotSerializer(sensitiveSerializer);
```

```javascript
// jest.config.js
module.exports = {
  snapshotSerializers: ['@platform-sec/sensitive-string-testing/serializer'],
};
```

A snapshot then keeps the shape of the structure and says what each sensitive
field is, without recording what it holds:

```
{
  "id": 1,
  "email": SensitiveString<sensitive:email>,
  "apiKey": SensitiveString<credential:api_key>,
  "phone": SensitiveString<sensitive>,
}
```

Without a serializer the same snapshot records whatever the class policy's
`redact()` returns, which loses the label, differs between projects, and changes
when a policy does. The rendering here is built from the class and the label,
which are public metadata. It never calls `reveal()`, never reads the policy,
and has no format placeholder for the value, so a value cannot reach a snapshot
through it even under a policy registered with `skipRedactValidation`.

For a different rendering:

```typescript
import { createSensitiveSerializer } from '@platform-sec/sensitive-string-testing';

createSensitiveSerializer({ showLength: true });
// SensitiveString<credential:api_key:len=32>

createSensitiveSerializer({ showExpiration: true });
// SensitiveString<credential:otp:EXPIRED>

createSensitiveSerializer({ format: '<{class}{label}>' });
// <credential:api_key>
```

`showLength` and `showExpiration` are off by default. A snapshot is committed to
version control, so the length of a credential is more than the class and the
label say about it, and whether a value is expired depends on when the test ran,
which makes a stored snapshot that records it stable only while the deadline
stays on the same side of the clock.

A `format` supersedes both options: the placeholders written in it decide what
appears. They are `{class}`, `{label}`, `{length}` and `{expired}`, and each
carries its own separator so the optional ones collapse cleanly. There is none
for the value, and an unknown one is rejected when the serializer is built
rather than passed through into every snapshot in the suite.

## Audit mocks

```typescript
import { mockRevealContext } from '@platform-sec/sensitive-string-testing';

const ctx = mockRevealContext('payment-handler', { fn: vi.fn });

token.reveal(ctx);

expect(ctx.calls).toHaveLength(1);
expect(ctx.calls[0]?.details.operation).toBe('reveal');
expect(ctx.auditReveal).toHaveBeenCalledTimes(1);
```

`calls` is recorded whether or not a spy factory is given. Passing `vi.fn` or
`jest.fn` additionally makes `auditReveal` a spy, so the framework's own call
assertions work on it. `reset()` clears both.

Each call also records `context`, the context that operation ran under, which is
where the tags an integration attaches to a reveal appear:

```typescript
expect(ctx.calls[0]?.context.tags).toEqual({ model: 'User', path: 'passwordHash' });
```

It is a copy of the descriptive fields rather than the context itself, one level
deep. A record pointing at the live mock context would close a cycle through
`calls`, which neither `JSON.stringify` nor a snapshot assertion could walk.

For assertions about a whole call path rather than a single operation:

```typescript
import { createMockAuditLog } from '@platform-sec/sensitive-string-testing';
import { withRevealContext } from '@platform-sec/sensitive-string-core';

const audit = createMockAuditLog();

await withRevealContext(audit.context, () => chargeCard(card));

expect(audit.getEntriesFor('card_number')).toHaveLength(1);
expect(audit.getEntriesByClass('credential')).toHaveLength(1);
```

An entry records the class, the label, the context name, and the operation. It
deliberately holds no raw value and no reference to the instance, because an
audit log is the thing most likely to end up in a failing assertion's output.

`contextName` is read from the context core reports the operation under, so a
reveal made under a nested child is recorded under the child's name rather than
the log's own.

## How these utilities read a value

A leak check needs the raw value to search for. Values this package created are
remembered when they are created, so a leak check does not have to reveal them:
that keeps the class policy's authorization hook and the caller's audit context
out of an assertion about output, and it lets a leak check run on a secret whose
deadline has already passed.

A value from anywhere else is revealed under an explicit named context, exported
as `TESTING_CONTEXT_NAMES`, so a strict `checkRevealAllowed` can allow those
four names in one place. If that reveal is refused, by a deadline or by a
policy, the check raises `UnreadableSecretError` saying it could not run, rather
than letting an `ExpiredSensitiveValueError` surface from inside an assertion
about output where it would read as a clean result. The registry is keyed by object identity and is not
reachable from outside this package: it adds no property to the instance and no
second way to the value. It does hold whatever is passed through the `value`
option, which is a reason to keep real secrets out of that option.

## Not included yet

- `createSingleUseSecret`, which needs the reveal counters from roadmap item
  1.4. There is nothing to exhaust until those exist.
- Streaming leak monitors, deferred by the design document.

## License

MIT
