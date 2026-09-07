# @platform-sec/sensitive-string-data

The shared layer under the data layer integrations: one bound-parameter walk, one query-log
redactor, one statement identifier scan, one driver error sanitizer, and one write reveal context.

You do not normally install this directly. Install the package for your ORM, which depends on this
one:

| ORM      | Package                                   |
| -------- | ----------------------------------------- |
| Prisma   | `@platform-sec/sensitive-string-prisma`   |
| Drizzle  | `@platform-sec/sensitive-string-drizzle`  |
| TypeORM  | `@platform-sec/sensitive-string-typeorm`  |

## Why this was extracted from three consumers rather than one

`sensitive-scrub` shipped in the same commit as `sensitive-sentry`, and `sensitive-secrets` shipped
in the same commit as `sensitive-vault`. Each was designed against a single first consumer and both
held up, because their consumers are homogeneous: every secret source is a fetch of one path, and
every error tracker takes an event and a hook.

ORM hooks are not homogeneous. A Drizzle `customType`, a TypeORM `ValueTransformer` and a Prisma
client extension have almost nothing in common at the seam, so a layer extracted from any one of
them would have encoded that one's shape. Three were written first, and every piece here differs
from what any single one of them had.

Two of those differences were gaps rather than preferences, and neither was visible to the suite of
the package that had it:

**The parameter walk.** TypeORM's descended into nested containers and terminated on cycles, but
walked only arrays and objects whose prototype is `Object.prototype`, so a `Map` or a bag from
another realm passed through unchecked. Drizzle's walked every object shape but stopped at one
level, so an instance inside a nested filter object passed through. Each package's development
driver could not produce the shape the other covered. The walk here does both.

**The error sanitizer.** Drizzle's rewrote `message` and `stack` as well as the parameter property,
because `DrizzleQueryError` interpolates the parameters into its message and V8 bakes that message
into the stack header at construction. TypeORM's rewrote only the structured property. That is
correct for TypeORM, whose message does not carry values, but the machinery for the case where it
does now exists once, tested once, for whichever consumer needs it next.

## What is deliberately not here

Three consumers proved these are not shared, so forcing them into this package would produce a
generalization of one ORM wearing three hats:

- **The column specification.** A path map with rules and a fallback in TypeORM, a model-keyed
  object in Prisma, a declaration on the column itself in Drizzle.
- **The drift check.** It reads entity metadata, the runtime data model, and registered column
  objects respectively, and there is no common input.
- **The `sensitive-scrub` fragments.** They name different properties on different errors.
- **The error types.** Each consumer keeps its own, because they carry different context, they are
  caught by different code, and their messages name the fix in that ORM's own vocabulary.

## What is here

### The bound-parameter walk

```typescript
import { findUnsafeParameter } from '@platform-sec/sensitive-string-data';

const found = findUnsafeParameter(params);
if (found !== undefined) {
  throw new MyOrmParameterRefusedError(found.path, found.kind, statement);
}
```

It reports rather than throwing, so each consumer raises its own error type. `found.path` is a
position: `2`, `email`, or `0.filters[1]` for a value inside a nested container.

### The query-log redactor and the statement scan

```typescript
import {
  indexClassifiedPaths,
  redactParameters,
  touchesClassifiedColumn,
} from '@platform-sec/sensitive-string-data';

const paths = indexClassifiedPaths(spec.fields);
const touched = touchesClassifiedColumn(sql, { paths });
inner.logQuery(sql, redactParameters(params, touched, '[REDACTED:parameter]'));
```

No SQL is parsed and none will be. The scan answers only whether a classified name appears in the
statement at all, which means the censoring it drives is positional-blind: a statement touching a
classified column loses all of its string parameters. Recovering the mapping would mean writing a
parser, and a parser that is wrong once is worse than a rule that is coarse always.

### The driver error sanitizer

```typescript
import { sanitizeQueryError } from '@platform-sec/sensitive-string-data';

const MY_QUERY_ERROR = {
  name: 'MyQueryError',
  identifyBy: ['query', 'params'],
  parameterKeys: ['params'],
  censor: '[REDACTED:parameter]',
  fallbackMessage: 'A query failed and its error could not be sanitized.',
};

throw sanitizeQueryError(error, MY_QUERY_ERROR);
```

Three properties of it are load bearing and each was learned from a driver rather than reasoned out.
It works through property descriptors, so a getter that would leak is never invoked. It rewrites in
place where the property allows it, because the error is a control-flow object that the ORM above
reads `code` from and application code runs `instanceof` on. And it rewrites `stack` whenever it
rewrites `message`: `Error.captureStackTrace` installs `stack` as an own accessor and it stays one,
so a sanitizer looking for `descriptor.value` finds nothing and rewrites nothing, while its tests
still pass because V8 formats the stack at first access from whatever `message` says by then. That
only holds while nothing read the stack first. One `console.error` between the throw and the catch
fixes the string with the plaintext in its header.

It never throws. Sanitizing happens while an error is already in flight, and throwing from here
destroys the error the user needed to see.

### The write reveal context

```typescript
import { buildWriteContext } from '@platform-sec/sensitive-string-data';

const context = buildWriteContext({
  sink: 'drizzle',
  table: 'users',
  column: 'email',
  operation: 'insert',
  klass: 'sensitive',
});
```

An ambient context set with `withRevealContext()` names the unit of work the caller cares about, so
its `name` and `reason` win; the sink, table, column and operation travel in the tags. The layering
goes through `createChildContext`, which is the part that is easy to get wrong: a context built from
scratch drops the ambient `auditReveal` hook and the caller's own tags, silently, so the reveals an
application thought it was recording stop arriving.

There is no refusal when no context is ambient. A row write happens on every request, and a package
that turns a missing context into a failed signup gets removed. What does not depend on this at all
is the redaction-marker refusal, which is what actually prevents corruption, and which lives in
`@platform-sec/sensitive-string-core`.

`WriteOperation` has six members and no consumer reaches all six. An entity mapper reaches every
one; a query builder reaches `insert`, `update` and `predicate` and has no state with which to
perform change detection. `unknown` is for the transformer shape, which is called with one argument
and is told nothing about the statement. A consumer that cannot tell passes `unknown` and says so in
its README rather than guessing `update`.

## What this package does not know about

It has no driver, no transport, and no vendor dependency, so its own suite runs against row objects
and error fixtures. It never retains a row, a result set, a driver object or an error beyond the
call that received it, and it holds no cache except the compiled matchers core owns.
