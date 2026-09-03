# @platform-sec/sensitive-string-nestjs

NestJS integration for SensitiveString: DTO fields are wrapped by a pipe, reveal context is
established by an interceptor, and response bodies are redacted on the way out.

## Installation

```bash
pnpm add @platform-sec/sensitive-string-nestjs
```

## Requirements

- Node.js 22.12+
- NestJS 10, 11, or 12 (`@nestjs/common`, `@nestjs/core`, `reflect-metadata`, `rxjs`)
- `@platform-sec/sensitive-string-core` (peer dependency)
- `class-validator` and `class-transformer` for the DTO examples below

`sensitive-string-core` is a peer dependency rather than a regular one on purpose. The pipe and the
response interceptor both test `instanceof SensitiveString`, which fails if the application and this
package resolve different copies of core.

## Quick Start

```typescript
// app.module.ts
import { Module, ValidationPipe } from '@nestjs/common';
import { APP_INTERCEPTOR, APP_PIPE } from '@nestjs/core';
import {
  SENSITIVE_CONTEXT_FACTORY,
  SensitiveContextInterceptor,
  SensitiveResponseInterceptor,
  SensitiveTransformPipe,
  type RevealContextFactory,
} from '@platform-sec/sensitive-string-nestjs';

const contextFactory: RevealContextFactory = (ctx) => {
  const req = ctx.switchToHttp().getRequest();

  return {
    name: `${req.method} ${req.path}`,
    auditReveal: (value) => logger.info('sensitive_access', { klass: value.klass }),
  };
};

@Module({
  providers: [
    // Validate plain strings first, then wrap.
    {
      provide: APP_PIPE,
      useFactory: () =>
        new ValidationPipe({
          transform: true,
          whitelist: true,
          validationError: { target: false, value: false },
        }),
    },
    { provide: APP_PIPE, useClass: SensitiveTransformPipe },

    { provide: SENSITIVE_CONTEXT_FACTORY, useValue: contextFactory },
    { provide: APP_INTERCEPTOR, useClass: SensitiveContextInterceptor },
    { provide: APP_INTERCEPTOR, useClass: SensitiveResponseInterceptor },
  ],
})
export class AppModule {}
```

```typescript
// login.dto.ts
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { Sensitive } from '@platform-sec/sensitive-string-nestjs';
import { IsEmail, IsString, MinLength } from 'class-validator';

export class LoginDto {
  @Sensitive('sensitive', 'email')
  @IsEmail()
  email!: SensitiveString<'sensitive'>;

  @Sensitive('credential', 'password')
  @IsString()
  @MinLength(8)
  password!: SensitiveString<'credential'>;
}
```

```typescript
// auth.controller.ts
@Controller('auth')
export class AuthController {
  @Post('login')
  @WithRevealContext({ name: 'user-authentication' })
  async login(@Body() dto: LoginDto) {
    // dto.email and dto.password are already SensitiveString instances, and
    // every reveal() below is audited under the merged context.
    return this.authService.authenticate(dto.email, dto.password);
  }
}
```

## Three Rules That Are Not Optional

Each of these is a way to get a working-looking application that leaks or breaks, so they come first
rather than in a footnotes section.

### 1. ValidationPipe runs before SensitiveTransformPipe

class-validator decorators validate plain strings. `@IsEmail()` and `@MinLength(8)` on a wrapped
value do not merely fail; with the pipes in the wrong order class-transformer tries to rebuild each
`SensitiveString` and the request fails outright with a 500.

Register both pipes through the same mechanism, either both in `useGlobalPipes` or both under
`APP_PIPE`. The relative order of a `useGlobalPipes` pipe and an `APP_PIPE` pipe is an implementation
detail of NestJS bootstrap, so mixing the two leaves the order undefined.

### 2. Turn off `validationError.value` and `validationError.target`

class-validator attaches the offending value and the whole target object to every `ValidationError`.
Any exception filter or custom `exceptionFactory` that serializes one echoes the secret back to the
client:

```typescript
new ValidationPipe({ validationError: { target: false, value: false } })
```

Nothing in this package can override that default from the outside, so it is part of the setup. For
the same reason, avoid `$value` in a custom constraint message.

### 3. Give every sensitive field a class-validator decorator

`@Sensitive` registers no class-validator metadata. Under `whitelist: true` a property carrying only
`@Sensitive` is stripped from the payload before the pipe ever sees it, and the handler receives
`undefined`. Add a real validator, or `@Allow()`:

```typescript
export class TokenDto {
  @Sensitive('credential', 'refresh_token')
  @Allow()
  refreshToken!: SensitiveString<'credential'>;
}
```

## What Gets Wrapped

`SensitiveTransformPipe` walks any parameter whose declared type is a user-defined class, which
covers `@Body()`, `@Query()`, and `@Param()` DTOs as well as GraphQL `@Args()`. It skips parameters
typed as `String`, `Number`, `Boolean`, `Array`, or `Object`, which is the same test `ValidationPipe`
applies before validating.

Within that parameter it wraps:

- Every `@Sensitive` property of the DTO, and of any nested value whose runtime class carries
  `@Sensitive` metadata
- Arrays of strings, element by element
- Properties inherited from a parent DTO class, which a subclass may re-decorate to change the class
  or label of one field

`@Sensitive` throws at class-definition time if it is applied to a static or a symbol-keyed property.
Neither can be populated by a request payload, and the only other symptom of either would be a field
that is quietly never wrapped.

It leaves alone:

- Values that are already `SensitiveString` instances, so running the pipe twice is safe
- Non-string values, which stay as they are rather than becoming a `"[object Object]"` credential.
  Rejecting the wrong type is `ValidationPipe`'s job
- Nested plain objects. A nested DTO is discovered by its runtime class, so it needs
  `@Type(() => NestedDto)` and `transform: true` for class-transformer to build that class first,
  which is the same requirement class-validator's `@ValidateNested()` already has

The pipe returns the instance it received rather than a copy, so the DTO prototype survives.

### The raw `request.body` is not wrapped

The pipe wraps the value injected into the handler parameter. The parsed body on the underlying
Express or Fastify request object keeps its plain strings. An application that logs `request.body`
from middleware or a logging interceptor needs `sensitive-express` or `sensitive-fastify`
underneath; this package does not cover that path.

## Reveal Context

`SensitiveContextInterceptor` opens an `AsyncLocalStorage` scope for the request, so `reveal()` calls
inside it are audited without threading a context through every function.

The request-level context comes from a `RevealContextFactory` registered under
`SENSITIVE_CONTEXT_FACTORY`. `@WithRevealContext` adds a per-handler or per-controller context on
top; method metadata overrides class metadata, `name`, `reason`, and `auditReveal` override the
request-level values, and `tags` are merged with the handler's winning on conflict. The decorator
also accepts a factory, which receives the `ExecutionContext`:

```typescript
@Post('refund/:orderId')
@WithRevealContext((ctx) => ({
  name: 'refund-processing',
  tags: { orderId: ctx.switchToHttp().getRequest().params.orderId },
}))
async refund(@Param('orderId') orderId: string) {}
```

Without the interceptor registered, `@WithRevealContext` is a no-op.

### What the scope covers

| Stage | Sees the context |
|---|---|
| Middleware, guards | No, they run before any interceptor |
| `intercept()` of an interceptor registered after this one | Yes |
| Pipes | Yes |
| The route handler | Yes |
| Response operators (`map`, `tap`) of an interceptor registered after this one | No |
| Exception filters | No |

The last row is the surprising one. NestJS emits the handler result from outside the region it bound
to the async context, and an inner interceptor's response operators run before this interceptor's own
boundary on the way out, so nothing here can restore it for them. Code in any of the "No" positions
passes an explicit context:

```typescript
value.reveal({ name: 'auth-guard', reason: 'checking API key' });
```

## Response Redaction

`SensitiveString.toJSON()` already redacts, so a JSON response is safe before this interceptor is
involved. `SensitiveResponseInterceptor` covers two cases `toJSON()` cannot. The first is something
serializing the body without `JSON.stringify`, and `ClassSerializerInterceptor` is the common one: its
`instanceToPlain` copies the public `klass` and `label` fields of a `SensitiveString` and drops the
`[REDACTED:...]` marker, so a client cannot tell a redacted field from a missing one. The second is a
`serialize()` result in the body. Its raw `value` is meant for service-to-service transport, and
`JSON.stringify` emits it faithfully; the interceptor replaces the whole object with the redaction of
the class it names.

Register it after any serializer. Interceptors process responses innermost first and later
registration is inner, so this order redacts before `instanceToPlain` runs:

```typescript
{ provide: APP_INTERCEPTOR, useClass: ClassSerializerInterceptor },
{ provide: APP_INTERCEPTOR, useClass: SensitiveResponseInterceptor },
```

The walk is core's `redactCopy`. It never mutates what the handler returned, since an entity may be
shared with an ORM identity map or a cache. It returns copies that keep each object's prototype,
passes `Buffer`, `Date`, `Map`, `Set`, `RegExp`, `URL`, and streams through untouched, and preserves
an object referenced twice as one shared reference rather than reporting the second occurrence as
circular. A `StreamableFile` returned from the handler is passed through before the walk.

Values reachable only through a prototype getter are not visited by the walk. Those are still
redacted by `toJSON()` during JSON serialization.

## Parameter Decorators

For sensitive data that arrives outside a DTO:

```typescript
import {
  SensitiveHeader,
  SensitiveParam,
  SensitiveQuery,
} from '@platform-sec/sensitive-string-nestjs';

@Controller('api')
export class ApiController {
  @Get('resource')
  async getResource(
    @SensitiveHeader('authorization', 'credential') auth: SensitiveString<'credential'> | null,
    @SensitiveQuery('api_key', 'credential') apiKey: SensitiveString<'credential'> | null,
  ) {}

  @Get('users/:userId')
  async getUser(
    @SensitiveParam('userId', 'sensitive') userId: SensitiveString<'sensitive'> | null,
  ) {}
}
```

Each yields `null` when the value is absent or empty, so the parameter type is nullable. A repeated
header or query parameter uses its first value. Leave `validateCustomDecorators` off: with it on,
class-validator is asked to validate a `SensitiveString` that carries no validation metadata, which
fails under `forbidUnknownValues`.

## Decorators, Legacy and Stage 3

NestJS requires legacy TypeScript decorators (`experimentalDecorators: true`,
`emitDecoratorMetadata: true`), and a file is compiled under one decorator model or the other.
`@platform-sec/sensitive-string-decorators` targets Stage 3 decorators, so the two packages share
names and semantics but no code, and this one has no dependency on it.

The mechanics differ too. There, `@Sensitive` wraps a value at assignment time through an accessor
decorator; here it records metadata and the pipe wraps. There, `@WithRevealContext` wraps the method
call; here it is metadata the interceptor reads.

## Not Covered

- Wrapping the raw `request.body` (see above)
- Reveal context in middleware, guards, and exception filters
- WebSocket gateways and microservice transports (`@MessagePattern`, `@EventPattern`)
- A `SensitiveZodPipe` for `sensitive-zod` users
- A `SensitiveModule.forRoot()` that encodes the ordering rules

## License

MIT
