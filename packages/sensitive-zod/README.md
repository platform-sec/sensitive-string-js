# @platform-sec/sensitive-string-zod

Zod integration for SensitiveString - parse and validate input directly into sensitive types at boundary layers.

## Installation

```bash
pnpm add @platform-sec/sensitive-string-zod zod
```

## Requirements

- Node.js 22.12+
- Zod 4.0+
- @platform-sec/sensitive-string-core (peer dependency)

Zod 3 is not supported. A v3 schema and a v4 schema cannot be composed in either direction, and the
failure is a raw `TypeError` at schema construction rather than a type error, so a peer range
admitting both majors would be a promise this package could not keep.

## Quick Start

```typescript
import { z } from 'zod';
import { zCredential, zSensitiveWithValidation } from '@platform-sec/sensitive-string-zod';

// Define schema with sensitive fields
const WebhookSchema = z.object({
  token: zCredential('session_token'),
  email: zSensitiveWithValidation('sensitive', z.email(), 'email'),
  note: z.string().optional(),
});

// Parse request body
const webhook = WebhookSchema.parse(req.body);

// Type inference works correctly
// webhook.token is SensitiveString<'credential'>
// webhook.email is SensitiveString<'sensitive'>

// Safe to serialize
res.json(webhook); // Sensitive fields automatically redacted
```

## Available Schemas

```typescript
// Generic sensitive string with specified class + label
zSensitiveString('sensitive', 'email')   // → SensitiveString<'sensitive'>
zSensitiveString('credential', 'token') // → SensitiveString<'credential'>

// Convenience shortcuts
zSensitive('email')        // → SensitiveString<'sensitive'>
zCredential('session_token') // → SensitiveString<'credential'>

// With custom validation
zSensitiveWithValidation('credential', z.string().min(32), 'api_key')

// Optional (returns null for missing)
zSensitiveOptional('sensitive', 'phone')

// Parse from serialized format
zSensitiveDeserialize('credential')
```

### Collections

Arrays and records wrap each element on its own, so the collection combinators still apply and a
failing element reports its own index or key.

```typescript
zSensitiveArray('email')                      // → SensitiveString<'sensitive'>[]
zCredentialArray('api_key').min(1).max(10)    // ZodArray, so .min() and friends work
zSensitiveStringArray('credential', 'token')  // explicit class

zSensitiveRecord('note')                      // → Record<string, SensitiveString<'sensitive'>>
zCredentialRecord('secret')                   // → Record<string, SensitiveString<'credential'>>
zSensitiveStringRecord('credential', 'secret')
```

Record keys stay in the clear. A key is a field name, not the secret, and redacting it would leave
the record impossible to look anything up in.

Nothing stops you writing `z.array(zCredential('api_key'))` by hand; the helpers are the same thing
with the label named once.

### Refinements over the raw value

`refineSensitive` runs a predicate against the raw string after wrapping. That read goes through
`reveal()`, so the ambient `RevealContext` authorizes it and its `auditReveal` hook records it with
`operation: 'reveal'`.

```typescript
const PasswordSchema = zCredential('password')
  .refineSensitive((raw) => raw.length >= 12, { message: 'Password must be at least 12 characters' })
  .refineSensitive((raw) => /[0-9]/.test(raw), { message: 'Password must contain a digit' });
```

The refinement manufactures no authority of its own. If a policy refuses a reveal without a context,
it refuses this one too; pass `params.context` to give the check a context of its own.

An async predicate is supported under `parseAsync`. Reached from a synchronous `parse()`, Zod throws
`$ZodAsyncError` rather than treating the pending promise as a pass.

The method is attached to the schemas this package builds. Standard Zod combinators return plain Zod
schemas and drop it, so refine before calling `.optional()` or `.array()`, or use the standalone
function:

```typescript
import { refineSensitive } from '@platform-sec/sensitive-string-zod';

refineSensitive(someSchema, (raw) => raw.startsWith('sk_'), { message: 'must start with sk_' });
```

### Normalizing before wrapping

Trimming a `SensitiveString` means revealing it. Normalizing during the parse keeps the whole
sequence on the raw string, with no reveal at all. Order is normalize, then validate, then wrap.

```typescript
zSensitivePreprocess({ trim: true, lowercase: true }, 'email', z.email());
zCredentialPreprocess({ stripWhitespace: true }, 'api_key');   // a key pasted with line breaks
zSensitivePreprocess([(v) => v.trim(), (v) => v.replace(/-/gu, '')], 'account_number');
```

Options are applied in the order `normalize`, `collapseWhitespace`, `stripWhitespace`, `trim`,
`lowercase` or `uppercase`. A function or a list of functions works in place of the options object.
Non-string input passes through untouched, so it still reports Zod's usual `invalid_type`.

### Defaults

The default is produced as a raw string and wrapped by the schema, so a generated fallback is
classified the same way a parsed one is. A function default is called once per parse that needs it.

```typescript
const Config = z.object({
  apiKey: zSensitiveDefault('credential', 'api_key', () => process.env.API_KEY ?? ''),
});
```

`undefined` triggers the default. `null` and `''` do not: they are values a client sent, and
treating them as absent would substitute a secret for input that should have been rejected.

The fallback is held in a closure rather than in a `z.string().default(...)`, and that placement is
load-bearing. `z.toJSONSchema(schema, { io: 'input' })` reads a schema definition's `default` and
emits it verbatim, calling a function default to do so, which is exactly what an OpenAPI
request-body generator does. Under a `.default()`, the example above would put the live
`process.env.API_KEY` into the published document.

The same reasoning applies to what you attach yourself. `z.toJSONSchema` emits `.meta({ examples })`
and `.meta({ description })` verbatim, and `z.literal(secret)` emits `const: "<secret>"`. Those are
yours to keep clean; `toJSONSchema`'s `override` callback is the documented escape hatch. On the
output side, a schema built by this package produces a `SensitiveString` and `toJSONSchema` refuses
with `Transforms cannot be represented in JSON Schema`, which is the right answer.

### Sensitivity decided by a sibling field

```typescript
const Setting = zConditionalSensitive({
  discriminator: 'type',
  valueField: 'value',
  conditions: {
    secret: { klass: 'credential', label: 'secret_data' },
    private: { klass: 'sensitive', label: 'private_data' },
    public: null,
  },
});

Setting.parse({ type: 'secret', value: 'sk-live-x' });  // value is SensitiveString
Setting.parse({ type: 'public', value: 'motd' });       // value is a string
```

The result is a `z.discriminatedUnion`, so an unknown discriminator is rejected before the value is
looked at. For payloads with more than these two fields, write the branches by hand; `zSensitive`
and `zCredential` work as object fields there with nothing extra.

## Errors That Do Not Echo the Input

Most of Zod's issues are already safe. A failed `min`, `email`, or `regex` check reports the rule,
not the string that failed it, and Zod 4 closed two leaks v3 had: the enum and literal codes both
became `invalid_value`, which carries the *allowed* set rather than what arrived. What is left,
measured against 4.5.4 with a canary:

| Issue code | What it carries |
|---|---|
| `unrecognized_keys` | unknown key names, in `keys` and in the message |
| `custom` | whatever a `superRefine` caller attached to `params` |
| `invalid_element` | the offending map key, in `key` |
| any | the value itself, in `input`, when the parse options set `reportInput: true` |

`invalid_union`, `invalid_key`, and `invalid_element` nest issue lists, so any of the above can
arrive one or more levels down.

The guarantee is about the input, not about values you put in your own schema. `invalid_value`
echoes what `z.literal()` and `z.enum()` were given, and `invalid_format` echoes the argument to
`startsWith`, `endsWith`, and `includes`. Nothing here can tell a secret apart from a legitimate
allowed value, so do not build a schema out of one. This is the same hazard as `z.literal(secret)`
under `z.toJSONSchema`, above.

That splits the fix in two. An error map can only rewrite the message. The `keys`, `params`, `key`,
and `input` fields survive it untouched and reach anything that serializes the error, which is where
structured logging picks them up.

```typescript
import { sensitiveSafeParse } from '@platform-sec/sensitive-string-zod';

const result = sensitiveSafeParse(LoginSchema, req.body);
if (!result.success) {
  res.status(400).json({ issues: result.error.issues });  // nothing echoed, message or field
}
```

`sensitiveParse` and `sensitiveSafeParseAsync` are the throwing and async counterparts. For an error
you already hold, `redactZodError` and `redactZodIssues` return redacted copies without touching the
originals. All three parse helpers take Zod 4's parse options, exported as `SensitiveParseOptions`;
they set `error` when you have not, and force `reportInput` off, since that option puts the raw value
back on every issue.

To cover schemas that never pass through these helpers, install the error map once at startup. It is
not installed on import: a library that reaches into a process's global Zod configuration behind the
application's back is worse than one that asks for a line of setup.

```typescript
import { installSensitiveErrorMap } from '@platform-sec/sensitive-string-zod';

installSensitiveErrorMap();
```

That still leaves the structured fields, so keep using `sensitiveSafeParse` at the boundary.

### Do not key a container by a secret

One channel is deliberately left uncovered: `issue.path`. A `z.object`, `z.record`, or `z.map` keyed
by a sensitive value puts that value in the path of every issue below it, and `z.treeifyError`
reproduces it as an object key.

```typescript
z.map(z.literal('k'), z.string()).safeParse(new Map([[secret, 'v']]));
// -> path: ['<the secret>']
```

Redacting `path` is not the fix: it is the only thing that makes a multi-issue error actionable, and
collapsing it would turn a form validation response into a list of unattributed complaints. Put the
secret in the value position instead, which is what `zSensitiveRecord` does. The failure is silent,
so it is worth checking for by hand.

## Examples

### User Registration

```typescript
const RegistrationSchema = z.object({
  email: zSensitivePreprocess({ trim: true, lowercase: true }, 'email', z.email()),
  password: zSensitiveWithValidation(
    'credential',
    z.string()
      .min(8, 'Password must be at least 8 characters')
      .regex(/[A-Z]/, 'Must contain uppercase')
      .regex(/[0-9]/, 'Must contain number'),
    'password'
  ).refineSensitive((raw) => !raw.toLowerCase().includes('password'), {
    message: 'Password must not contain the word "password"',
  }),
  fullName: zSensitive('name'),
  phone: zSensitiveOptional('sensitive', 'phone'),
  backupCodes: zCredentialArray('backup_code').length(10),
});

const result = sensitiveSafeParse(RegistrationSchema, req.body);
```

### API Authentication

```typescript
const AuthHeaderSchema = z.object({
  authorization: zCredential('auth_header'),
});

const headers = AuthHeaderSchema.parse(req.headers);
```

### Service-to-Service Communication

```typescript
// Receiving service
const PayloadSchema = z.object({
  userId: z.string(),
  token: zSensitiveDeserialize('credential'),
});

const { token } = PayloadSchema.parse(req.body);
// token is SensitiveString<'credential'>, reconstructed from serialized form
```

A class mismatch, an unregistered class, and a malformed payload are all reported as Zod issues, so
`safeParse` reports them rather than throwing.

## Re-exports

For convenience, this package re-exports commonly used items from `@platform-sec/sensitive-string-core`:

- `SensitiveString`
- `SensitivityClass`
- `SerializedSensitiveString`
- `RevealContext`
- `withRevealContext`
- `getCurrentRevealContext`
- `safeLog`
- `redactInStructure`

## License

MIT
