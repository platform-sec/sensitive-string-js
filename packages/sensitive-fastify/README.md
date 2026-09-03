# @platform-sec/sensitive-string-fastify

Fastify integration for SensitiveString: a JSON Schema keyword wraps a property during validation, a
field map covers routes without one, sensitive headers are extracted without touching
`request.headers`, the reveal context is established once per request, and response bodies are
redacted on the way out.

## Installation

```bash
pnpm add @platform-sec/sensitive-string-fastify
```

## Requirements

- Node.js 22.12+
- Fastify 5 (peer dependency)
- `@platform-sec/sensitive-string-core` (peer dependency)

`sensitive-string-core` is a peer dependency rather than a regular one on purpose. The response
filter tests `instanceof SensitiveString`, which fails if the application and this package resolve
different copies of core.

Fastify 4 is out of range. It is past end of life, and this package relies on v5 surfaces:
`request.routeOptions`, and the rule that a request decorator holding a reference type has to be
declared through a getter.

## Quick Start

```typescript
import Fastify from 'fastify';
import { sensitiveKeyword, sensitivePlugin } from '@platform-sec/sensitive-string-fastify';

// 1. The keyword goes into the constructor. Ajv is built with the instance, so a
//    plugin cannot add a keyword afterwards.
const fastify = Fastify({
  logger: true,
  ajv: { customOptions: { keywords: [sensitiveKeyword] } },
});

// 2. Context, headers, and the response filter for the whole application
await fastify.register(sensitivePlugin, {
  context: (request) => ({
    name: `${request.method} ${request.routeOptions.url}`,
    tags: { requestId: request.id },
    auditReveal: (value, details) => audit.record(value, details, request),
  }),
  headers: { authorization: 'credential' },
  responseFilter: true,
});

// 3. A schema-first route: the keyword wraps during validation
fastify.post<{ Body: LoginBody }>(
  '/api/auth/login',
  {
    schema: {
      body: {
        type: 'object',
        required: ['email', 'password'],
        properties: {
          email: { type: 'string', format: 'email', sensitive: { klass: 'sensitive' } },
          password: { type: 'string', minLength: 8, sensitive: { klass: 'credential' } },
        },
      },
    },
  },
  async (request) => {
    const { email, password } = request.body; // both already SensitiveString

    request.log.info({ body: request.body });
    // {"body":{"email":"[REDACTED:sensitive]","password":"[REDACTED:credential]"}}

    const user = await authenticateUser(email, password);

    return { success: true, userId: user.id };
  }
);

// 4. Schema-less routes under a prefix: the field map, scoped by encapsulation
await fastify.register(
  async function webhooks(instance) {
    await instance.register(sensitivePlugin, {
      body: { 'additionalData.hmacSignature': 'credential' },
    });

    instance.post('/notification', handleNotification);
  },
  { prefix: '/webhooks/psp' }
);

await fastify.listen({ port: 3000 });
```

The two halves are independent. The keyword needs no plugin registration, and the plugin needs no
keyword.

## Scope, and why there is no `routes` option

The plugin is wrapped with `fastify-plugin`, so what it installs applies to the scope it is
registered in and to every child of that scope. Registering it at the root covers the application;
registering it inside a plugin covers that plugin's routes and nothing else. That is Fastify's own
matcher, which is why there is no prefix-matching option to configure.

Registering it twice, once at the root for context and responses and once in a child for a field map,
is the expected pattern and is safe. Each registration installs only the hooks its options ask for,
the request decorator is added once per scope, and a field an outer registration already wrapped is
left alone by an inner one.

## Hook order

Where each piece runs, and what that decides for other plugins. Instance-level hooks run in
registration order, parent scope before child scope, and all of them before a route's own hooks of
the same kind.

| Lifecycle position | This package | Consequence |
| --- | --- | --- |
| `onRequest` | Context (default position), header extraction | Both see headers; neither sees a body |
| `preValidation` | | A strategy that reads the body as strings runs here unaffected; `@fastify/passport` documents this position for `authenticate` |
| Validation | Keyword wrapping, per property, after that property's own checks | Everything after validation sees instances for keyword-declared properties |
| `preHandler`, instance level | Field map and route config wrapping | Instance hooks registered earlier see strings, later ones see instances |
| `preHandler`, route level | | Runs after every instance-level hook, so it sees instances. A route-level `preHandler` that reads a wrapped field as a string moves to `preValidation` or reveals explicitly |
| Handler | | Instances |
| `preSerialization` | Response filter | Not run for strings, buffers, streams, or errors |
| Error handler | | Inside the context scope for errors thrown after the context hook |

Anything that logs the request should run after wrapping. Fastify's own request log line carries the
method, url, host, and remote address, and no body or headers.

Applications validating with `fastify-type-provider-zod` can skip the ordering question for the body:
`sensitive-zod` schemas validate and wrap in one step.

## The schema keyword

```typescript
const fastify = Fastify({ ajv: { customOptions: { keywords: [sensitiveKeyword] } } });
```

With the keyword registered, any string property carrying `sensitive` in a body, querystring, or
params schema arrives in the handler as a `SensitiveString`.

- **It applies to string values only.** Ajv runs `type`, `minLength`, `format`, and the property's
  other keywords on the raw string first, and a failing check produces the usual 400 with no value in
  the message. The keyword then replaces the value in its parent object.
- **It follows the schema.** Nested objects, array items, `$ref` to schemas added with
  `fastify.addSchema`, the querystring, and params are all reached, because `request.query` and
  `request.params` are plain mutable objects in Fastify.
- **The label defaults to the property name.** An array item is addressed by index rather than by
  name, so it takes the label the schema gives it, or none.
- **A typo fails at startup.** The keyword's own schema is validated by a `metaSchema`, so
  `sensitive: { class: 'credential' }` is a route-registration failure rather than a first-request
  surprise.

Two places it must not go:

- **A headers schema.** The value it would replace lives in the raw Node headers object, which
  Fastify itself reads as strings. The plugin's `onRoute` hook refuses such a route; use the `headers`
  option instead. That guard sees only routes registered after the plugin loaded, so the rule matters
  as much as the check.
- **A response schema**, where it is simply inert. `fast-json-stringify` ignores it. Use
  `responseFilter`.

Under a custom validator compiler (`setValidatorCompiler`, a TypeBox or Zod type provider) the
keyword is absent and nothing is wrapped. Those applications use the `body` option, or a schema
library that transforms during validation.

## Body wrapping without a schema

```typescript
const AUTH_FIELDS = {
  password: 'credential',
  email: { klass: 'sensitive', label: 'email' },
  'creditCard.number': 'credential',
  'creditCard.cvv': 'credential',
} as const;

// Scope-wide: every route in this plugin and its children
await fastify.register(
  async function authRoutes(instance) {
    await instance.register(sensitivePlugin, { body: AUTH_FIELDS });

    instance.post('/login', handleLogin);
    instance.post('/register', handleRegister);
  },
  { prefix: '/api/auth' }
);

// Per route: honoured by any registration whose scope contains the route
fastify.post(
  '/api/keys',
  { config: { sensitive: { body: { apiKey: 'credential' } } } },
  async (request) => {
    /* apiKey is wrapped */
  }
);
```

Both are applied by one instance-level `preHandler` per registration, which is the last instance-level
position before the handler. `onRoute` would have been tidier and misses routes: it fires
synchronously at route registration, so routes declared before the plugin, and routes declared after a
`register()` that was not awaited, are never seen. The instance-level hook reaches all of them.

The cost of that choice is one property read and one cache lookup per request on a route that declares
nothing. The merged map is cached against `request.routeOptions.config`, which is one stable object
per route, so it is computed once per route rather than once per request.

The field map is core's `SensitiveFieldConfig`, and the wrap is core's `wrapSensitiveByPath`, so this
inherits that function's behaviour:

- **Labels default to the last path segment**, so `'creditCard.number'` produces label `number`.
- **Idempotent.** An existing `SensitiveString` at a configured path is left alone, and a body whose
  configured paths are all already wrapped is not cloned at all.
- **Non-string values are skipped.** `{ "pin": 1234 }` stays a number. Coercing would silently change
  the type a validator agreed to.
- **No wildcards.** Paths are literal dot notation, with array elements addressable by index.
- **Prototype keys are refused.** A path containing `__proto__`, `constructor`, or `prototype` is
  rejected when the plugin is registered, rather than silently matching nothing.

A scope map is validated at registration; a route's `config.sensitive.body` is validated the first
time a request reaches that route, because that is when the plugin first sees it.

## Header extraction

```typescript
await fastify.register(sensitivePlugin, {
  headers: {
    authorization: 'credential',
    'x-api-key': { klass: 'credential', label: 'api_key' },
  },
});

fastify.get('/api/data', async (request) => {
  const auth = request.sensitive.headers['authorization']; // SensitiveString | null
  // request.headers.authorization is still the plain string
});
```

`request.headers` is left byte-identical, and the wrapped copies go on `request.sensitive.headers`.
Fastify reads `request.headers` itself, and so does every authentication and CORS plugin; replacing
`authorization` with an object breaks anything that calls `startsWith('Bearer ')` on it. The NestJS
package made the same choice, and so does the Express one.

Names are matched case-insensitively and read back in lower case, which is how Node stores them. A
header that reaches Node as an array contributes its first element. An absent or empty header becomes
`null` through `SensitiveString.fromOptional`, so an empty header is not mistaken for a credential of
length zero. The container has a null prototype, so a header named `constructor` is an ordinary key.

`request.sensitive` is a getter added with `decorateRequest`, and it is typed by declaration merging
on `FastifyRequest`. On a route no `headers` option applies to it reads an empty frozen container
rather than `undefined`, so the type is honest wherever the plugin is registered. On a route in a
scope where the plugin was never registered the decorator does not exist at all, and the property is
`undefined` despite the type.

**The limitation, stated rather than hidden:** code that logs `request.headers` still sees the raw
`authorization` value. That is a logger configuration concern, such as pino's
`redact: ['req.headers.authorization']`, and this package does not claim to close it.

## Reveal context

```typescript
await fastify.register(sensitivePlugin, {
  context: (request) => ({
    name: `${request.method} ${request.routeOptions.url}`,
    tags: { requestId: request.id, ip: request.ip },
    auditReveal: (value, details) => {
      request.log.info({
        event: 'sensitive_access',
        operation: details.operation, // 'reveal' | 'mask' | 'renew'
        klass: value.klass,
        label: value.label,
      });
    },
  }),
});
```

The hook is the callback form, and the callback is what carries the scope: Fastify continues the
lifecycle synchronously from `done()`, so every later hook, the handler, each continuation after an
`await` in it, `preSerialization`, `onSend`, `onResponse`, and the error handler all run inside it.
An async hook cannot do this, because `AsyncLocalStorage.run` inside one ends when the hook returns.
This is the idiom `@fastify/request-context` uses.

What does not inherit the context: hooks registered before this plugin in the same scope, and hooks
in a parent scope, both of which run first.

The name uses `request.routeOptions.url`, the route pattern, rather than `request.url`, which carries
the query string and with it any token that arrived there.

`contextHook` moves the hook to `'preValidation'` or `'preHandler'`. The default `onRequest` covers
the most and sees the least: no body, and no `request.user` from an authentication plugin. Tags that
depend on the authenticated user are better added in the handler with core's `createChildContext`,
because moving the hook to `preHandler` leaves a 400 from validation outside the scope.

The factory is synchronous. The hook has to call `done()` inside the scope it opened, and an awaited
factory would have to reproduce that arrangement by hand. A factory returning `undefined` establishes
no context for that request rather than an empty one, so a policy whose `checkRevealAllowed` rejects a
missing context still rejects.

## Response redaction

```typescript
await fastify.register(sensitivePlugin, { responseFilter: true });

fastify.get('/api/user/profile', async (request) => {
  const user = await db.getUser(request.user.id);

  return {
    id: user.id,
    email: user.email, // SensitiveString   -> '[REDACTED:sensitive]'
    token: user.token.serialize(), // serialized value -> '[REDACTED:credential]'
  };
});
```

This is defense in depth, and it is opt-in for that reason. Both of Fastify's serializers already
redact an instance on their own: the default `JSON.stringify` path honours `toJSON()`, and the
response-schema path (`fast-json-stringify`) calls `toString()` for a string-typed property and
`toJSON()` for an untyped one. The filter earns its place for the two cases neither can cover:

- **Serialized values.** `serialize()` produces `{ __sensitive: true, klass, value }` carrying the raw
  value, intended for service-to-service transport. One placed in a client response leaked in every
  configuration measured: no schema, an untyped property, and an object-typed property declaring
  `value`. The filter replaces any object carrying that marker with the class's redaction.
- **Entity instances.** A body that is a class instance (ORM entity, DTO) is copied with its prototype
  preserved, so an entity `toJSON()` still runs and a serializer's `instanceof` checks still see the
  class.

The walk is core's `redactCopy`, the same one the NestJS `SensitiveResponseInterceptor` uses. It never
mutates the body, since an entity may be shared with an ORM identity map, and it memoizes copies, so a
reference appearing twice stays one shared reference while a genuine cycle produces a cyclic copy that
fails at serialization exactly as the original would. `Date`, `Map`, `Set`, `RegExp`, `URL`, `Buffer`,
and streams pass through.

What it does not reach: Fastify runs no `preSerialization` hook for a string, `Buffer`, or stream
payload, or for an error reply. An error reply is serialized from `statusCode`, `code`, `error`, and
`message`, and a message that interpolates an instance carries the redaction marker rather than the
value. A response schema still applies after the filter, so an instance at a property the schema types
as `object` comes out as `{}`, which loses the marker and leaks nothing.

What it cannot do is recover a value already revealed into a plain string.
`{ email: user.email.reveal() }` sends the email, by design.

## Parse errors need no scrubbing

Express's body-parser attaches the unparsed body to its 400, which is why the Express package ships a
scrubber. Fastify's `FST_ERR_CTP_INVALID_JSON_BODY` carries `code`, `name`, `statusCode`, and
`message` only, and the message does not quote the input. Measured with a trailing comma, an unquoted
value, and a truncated body, neither the response nor the log line contained the canary.

## Typing `request.body`

Fastify types `request.body` as `unknown` unless the route declares a `Body` generic or a type
provider is installed. Declare it with the wrapped types, which is what the keyword and the field map
both produce:

```typescript
interface LoginBody {
  email: SensitiveString<'sensitive'>;
  password: SensitiveString<'credential'>;
}

fastify.post<{ Body: LoginBody }>('/api/auth/login', { schema }, async (request) => {
  const raw = request.body.password.reveal();
});
```

A type provider that derives this from the schema is the right end state and is not here yet. Under
`noPropertyAccessFromIndexSignature`, `request.sensitive.headers` is read with brackets.

## Not covered

- **Query parameters, route parameters, and cookies through the field map.** The keyword already
  covers query and params; a `query` option is cheap once there is a use case. Cookies follow the
  headers shape once `@fastify/cookie` is in the picture.
- **Multipart bodies.** `@fastify/multipart` with `attachFieldsToBody` produces a different shape.
- **Wildcards in field paths.** They belong in core's path helpers, so `unwrapSensitiveByPath` and
  `checkSensitiveFieldsWrapped` gain them at the same time.
- **A type provider that understands the keyword**, and a `WrappedBody<T, Fields>` helper for
  field-map users.
- **`request.headers` redaction**, and anything a revealed plain string does after `reveal()`.

## License

MIT
