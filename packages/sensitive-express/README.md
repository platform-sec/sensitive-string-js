# @platform-sec/sensitive-string-express

Express integration for SensitiveString: configured body fields are wrapped at the middleware
layer, sensitive headers are extracted without touching `req.headers`, the reveal context is
established once per request, response bodies are redacted on the way out, and a parse error stops
carrying the raw body it failed on.

## Installation

```bash
pnpm add @platform-sec/sensitive-string-express
```

## Requirements

- Node.js 22.12+
- Express 4.21+ or 5 (peer dependency)
- `@platform-sec/sensitive-string-core` (peer dependency)

`sensitive-string-core` is a peer dependency rather than a regular one on purpose. The response
filter tests `instanceof SensitiveString`, which fails if the application and this package resolve
different copies of core.

## Quick Start

```typescript
import express from 'express';
import {
  sensitiveBody,
  sensitiveContext,
  sensitiveHeaders,
  sensitiveResponseFilter,
  stripParseErrorBody,
} from '@platform-sec/sensitive-string-express';

const app = express();

// 1. Parse, and keep parse failures from carrying the raw body
app.use(express.json());
app.use(stripParseErrorBody());

// 2. Reveal context for everything below
app.use(
  sensitiveContext((req) => ({
    name: `${req.method} ${req.path}`,
    tags: { requestId: req.headers['x-request-id'] },
    auditReveal: (value, details) => audit.record(value, details, req),
  }))
);

// 3. Headers, extracted without touching req.headers
app.use(sensitiveHeaders({ fields: { authorization: 'credential' } }));

// 4. Response redaction
app.use(sensitiveResponseFilter());

// 5. Body wrapping, mounted where the sensitive routes live
app.use(
  '/api/auth',
  sensitiveBody({ fields: { password: 'credential', email: 'sensitive' } })
);

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body; // both already SensitiveString

  console.log(req.body);
  // { email: SensitiveString<sensitive:email> { [REDACTED:sensitive] },
  //   password: SensitiveString<credential:password> { [REDACTED:credential] } }

  const user = await authenticateUser(email, password);

  res.json({ success: true, userId: user.id });
});

app.listen(3000);
```

## Middleware order

`sensitiveBody` replaces strings with objects, so anything that reads the body as strings has to run
before it:

| Must run before `sensitiveBody` | Why |
| --- | --- |
| `express.json()`, `express.urlencoded()` | There is no body to wrap until a parser has produced one |
| Schema validators (express-validator, a `z.string()` schema) | They expect strings; a `SensitiveString` fails `typeof === 'string'` |
| Strategies that read the body (passport-local) | They pass `req.body.password` to `bcrypt.compare`, which throws on a non-string |
| CSRF middleware reading `req.body._csrf` | Same reason |

Anything that *logs* the request should run after it: a request logger placed before the wrapper
sees plain strings.

Applications validating with Zod can skip the ordering problem entirely. `sensitive-zod` schemas
validate and wrap in one step, which makes `sensitiveBody` unnecessary for those routes.

`sensitiveHeaders`, `sensitiveContext`, and `sensitiveResponseFilter` have no ordering constraints
among themselves or with third-party middleware, because none of them changes what the framework or
another middleware reads.

## Body wrapping

```typescript
const AUTH_FIELDS = {
  password: 'credential',
  email: { klass: 'sensitive', label: 'email' },
  'creditCard.number': 'credential',
  'creditCard.cvv': 'credential',
  'items.0.secret': 'credential',
} as const;

app.use('/api/auth', sensitiveBody({ fields: AUTH_FIELDS }));
```

Scope comes from the mount path, `app.use(path, ...)`, which is Express's own matcher on every
major. There is no `routes` option: Express 5 rejects the `/api/auth/*` pattern the first draft of
this package would have needed, because path-to-regexp 8 requires a named wildcard.

The field map is core's `SensitiveFieldConfig`, and the wrap is core's `wrapSensitiveByPath`, so the
middleware inherits that function's behaviour:

- **Labels default to the last path segment**, so `'creditCard.number'` produces label `number`.
  Pass `{ klass, label }` where that is not descriptive enough.
- **Idempotent.** An existing `SensitiveString` at a configured path is left alone, so a global
  mount plus a per-route one wraps once.
- **Non-string values are skipped.** `{ "pin": 1234 }` stays a number. Coercing would silently
  change the type a validator agreed to; requiring a string is the schema's job.
- **No wildcards.** Paths are literal dot notation, with array elements addressable by index.
- **Prototype keys are refused.** A path containing `__proto__`, `constructor`, or `prototype` is
  rejected when the middleware is constructed, rather than silently matching nothing.

`contentTypes` defaults to `['application/json', 'application/x-www-form-urlencoded']` and is matched
with `req.is()`. A request of any other type is left alone, as is a body that is absent (`undefined`
on Express 5, `{}` on Express 4) or not an object.

The field map is validated once, when the middleware is constructed. A typo is a startup failure,
not a field that quietly stays a plain string for the life of the process.

## Header extraction

```typescript
app.use(
  sensitiveHeaders({
    fields: {
      authorization: 'credential',
      'x-api-key': { klass: 'credential', label: 'api_key' },
    },
  })
);

app.get('/api/data', (req, res) => {
  const auth = req.sensitive.headers['authorization']; // SensitiveString | null
  // req.headers.authorization is still the plain string
});
```

`req.headers` is left byte-identical, and the wrapped copies go on `req.sensitive.headers`. Express
itself reads `req.headers` through `req.get()`, `req.is()`, and `req.fresh`, and so does every
authentication and CORS middleware; replacing `authorization` with an object breaks anything that
calls `startsWith('Bearer ')` on it. The NestJS package made the same choice for headers, query, and
params.

Names are matched case-insensitively and read back in lower case, which is how Node stores them. A
header that reaches Node as an array contributes its first element. An absent or empty header
becomes `null` through `SensitiveString.fromOptional`, so an empty header is not mistaken for a
credential of length zero.

`req.sensitive` is typed by declaration merging on `Express.Request`, the same idiom Passport uses
for `req.user`. Under `noPropertyAccessFromIndexSignature` the container is read with brackets, as
above.

The merged property is declared non-optional, which is a deliberate trade and worth knowing about:
`req.sensitive.headers['x']` type-checks in every handler, including one on a route where
`sensitiveHeaders` was never mounted, and there it is a runtime `TypeError` rather than a compile
error. Mount the middleware where the routes that read it live, or read it as `req.sensitive?.headers`
on routes where you are not sure.

**The limitation, stated rather than hidden:** a request logger that dumps `req.headers` still sees
the raw `authorization` value. That is a logger configuration concern, such as pino's
`redact: ['req.headers.authorization']`, and this package does not claim to close it.

## Reveal context

```typescript
app.use(
  sensitiveContext((req) => ({
    name: `${req.method} ${req.path}`,
    tags: { requestId: req.headers['x-request-id'], ip: req.ip },
    auditReveal: (value, details) => {
      logger.info('sensitive_access', {
        operation: details.operation, // 'reveal' | 'mask' | 'renew'
        klass: value.klass,
        label: value.label,
        path: req.path,
      });
    },
  }))
);

app.post('/api/auth/login', async (req, res) => {
  const password = req.body.password.reveal(); // audited through the request context
});
```

The scope is wide because Express calls `next()` synchronously. Every later middleware, the route
handler, the continuations after each `await` in it, and any error handler inherit the context. The
error handler holds whichever way the error arrived: `next(err)`, a synchronous throw, or a rejected
async handler. Express catches a throw at the layer that threw, so the `next(err)` it makes still
runs inside this scope.

Middleware registered before `sensitiveContext` does not inherit it. An event listener on `req` or
`res` is a separate question: a listener is a plain function, so it runs in whatever context is
active when the event fires, not where it was registered. `finish` emitted from inside `res.end()`
is still inside the scope; an event arriving after the handler has returned is not. Code that
reveals a value off the request path should pass an explicit `RevealContext`.

A factory returning `undefined` establishes no context for that request rather than an empty one, so
a policy whose `checkRevealAllowed` rejects a missing context still rejects.

## Response redaction

```typescript
app.use(sensitiveResponseFilter());

app.get('/api/user/profile', async (req, res) => {
  const user = await db.getUser(req.params.id);

  res.json({
    id: user.id,
    email: user.email, // SensitiveString      -> '[REDACTED:sensitive]'
    token: user.token.serialize(), // serialized value -> '[REDACTED:credential]'
  });
});
```

This is defense in depth, and it is opt-in for that reason. `toJSON()` already redacts a
`SensitiveString` whenever `JSON.stringify` reaches it. The filter earns its place for the two cases
that method cannot cover:

- **Serialized values.** `serialize()` produces `{ __sensitive: true, klass, value }` carrying the
  raw value, intended for service-to-service transport. One placed in a client response is a leak
  `JSON.stringify` would emit faithfully. The filter replaces any object carrying that marker with
  the class's redaction.
- **Entity instances.** A body that is a class instance (ORM entity, DTO) is copied with its
  prototype preserved, so an entity `toJSON()` still runs and a serializer's `instanceof` checks
  still see the class.

`res.send(object)` delegates to `res.json` in Express and is covered. `res.send(string)` is not
touched, and neither is a value that was already revealed: `res.json({ email: user.email.reveal() })`
sends the email, by design.

The walk is core's `redactCopy`, the same one the NestJS `SensitiveResponseInterceptor` uses. It
never mutates the body, since an entity may be shared with an ORM identity map, and it memoizes
copies, so a reference appearing twice stays one shared reference while a genuine cycle produces a
cyclic copy that fails at `JSON.stringify` exactly as the original would. `Date`, `Map`, `Set`,
`RegExp`, `URL`, `Buffer`, and streams pass through.

## Parse error scrubbing

```typescript
app.use(express.json());
app.use(stripParseErrorBody());
```

When `express.json()` cannot parse a body it raises a 400 and attaches the unparsed text to the
error as `err.body`, so a login request with a stray comma leaves the password on an object headed
for an error handler and a log shipper. Nothing has wrapped anything yet at that point, which is why
this belongs directly after the parser. The rest of the error, its status, type, and message, is
passed on unchanged.

It strips `body` from every error that reaches it, not only body-parser's. That is the safe default
for a scrubber, and top-level `err.body` is close to body-parser's signature in practice: an axios
error carries `err.response.data`, a `got` error `err.response.body`, and neither is touched. An
error of your own that carries a meaningful top-level `body` will lose it, so mount the scrubber
directly after the parser rather than at the end of the chain.

A `body` property that cannot be deleted is overwritten instead, and one that can be neither deleted
nor overwritten is left alone and the error still travels on. A `TypeError` thrown from inside an
error handler would lose the error entirely, which is worse than the leak.

## Express 4 and 5

The peer range is `^4.21.0 || ^5.0.0`, and the suite runs against both: everything against Express 5,
plus a smoke test of the whole stack against Express 4 through a devDependency alias. Three surfaces
diverge between the majors, and this package avoids all of them:

| Surface | Express 4 | Express 5 | How this package handles it |
| --- | --- | --- | --- |
| `req.body` with nothing parsed | `{}` | `undefined` | Both mean nothing to wrap |
| `req.query` | Own property, assignable | Prototype getter, no setter | Not touched |
| Route pattern `/api/auth/*` | Valid | Rejected; a wildcard must be named | No `routes` option; mount with `app.use(path, ...)` |

## Not covered

- **Query parameters, route parameters, and cookies.** Query and params need an extraction API
  rather than mutation (Express 5 gives `req.query` no setter, and `req.params` is computed per
  matched layer, so a global mount sees nothing). Cookies are deferred for scope.
- **Wildcards in field paths.** They belong in core's path helpers, so `unwrapSensitiveByPath` and
  `checkSensitiveFieldsWrapped` gain them at the same time.
- **Multipart bodies.** Different parsers produce different shapes.
- **Type inference over `req.body`.** Express fixes the `Request<P, ResBody, ReqBody>` generic at the
  handler, and middleware cannot narrow it. Annotate the handler, or cast.
- **`req.headers` redaction**, and anything a revealed plain string does after `reveal()`.

## License

MIT
