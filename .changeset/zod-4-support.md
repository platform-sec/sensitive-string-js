---
'@platform-sec/sensitive-string-zod': minor
---

Move to Zod 4. The peer range is now `zod@^4.0.0`; Zod 3 is not supported, because a v3 schema and a
v4 schema cannot be composed in either direction and the failure is a raw `TypeError` at schema
construction rather than a type error.

Three security-relevant changes come with the port:

- `zSensitiveDefault` holds its fallback in a closure instead of a `z.string().default(...)`.
  `z.toJSONSchema(schema, { io: 'input' })` reads a schema definition's `default` and emits it
  verbatim, calling a function default to do so, which put the live value of a default such as
  `() => process.env.API_KEY` into any generated OpenAPI document. Every documented behaviour of the
  helper is unchanged.
- `error-map.ts` is re-derived from Zod 4's issue shapes rather than translated. The enum and literal
  branches are gone, because v4 closed those leaks upstream. `redactZodError` now recurses into the
  issue lists nested under `invalid_key` and `invalid_element` as well as `invalid_union`, redacts
  `invalid_element.key`, and strips `input` from every issue.
- The three parse helpers use v4's `error` parse option in place of `errorMap`, which v4 accepts and
  silently ignores, and force `reportInput` off.

The suite now enumerates every issue code Zod 4 can emit, ties that table to `z.ZodIssueCode` so a
code added upstream fails the build rather than going unredacted, and asserts that a schema this
package builds emits a canary-free JSON Schema on the input side and refuses the output side.

Two API changes, both accepting strictly more than before: `zSensitiveWithValidation` and the three
`*Preprocess` helpers take any string-to-string schema rather than a `z.ZodString`, so Zod 4's format
constructors (`z.email()`, `z.uuid()`) work without falling back to the deprecated
`z.string().email()` spelling. `SensitiveParseOptions` is exported for callers who name the parse
options type.
