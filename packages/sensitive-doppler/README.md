# @platform-sec/sensitive-string-doppler

Doppler as a `SecretSource`: every secret arrives as a `SensitiveString`, the service token is
itself a `SensitiveString`, and the keys that are ordinary configuration stay ordinary strings.

## Installation

```bash
pnpm add @platform-sec/sensitive-string-doppler
```

## Requirements

- Node.js 22.12+
- `@platform-sec/sensitive-string-core` (peer dependency)
- `@platform-sec/sensitive-string-secrets` (peer dependency)

There is no vendor SDK. The API surface this package needs is one endpoint over `fetch`, so the
transport is built in and its interface is exported for a caller who wants their own with retries,
mTLS or a proxy already configured. This package has no third-party runtime dependencies.

## Usage

```typescript
import { DopplerSecretSource } from '@platform-sec/sensitive-string-doppler';

const doppler = new DopplerSecretSource({
  token: dopplerToken,        // SensitiveString<'credential'>
  project: 'payments',
  onLoad: (event) => audit.info('secret.load', event),
});

const config = await doppler.getAll('prod', {
  fields: { DOPPLER_PROJECT: 'plain', DOPPLER_CONFIG: 'plain', DOPPLER_ENVIRONMENT: 'plain' },
  rules: [{ pattern: /KEY|TOKEN|SECRET|PASSWORD|DSN/i, klass: 'credential' }],
  fallback: 'plain',
});

config.fields.get('STRIPE_SECRET_KEY');   // SensitiveString<credential:payments/prod#STRIPE_SECRET_KEY>
config.plain.get('LOG_LEVEL');            // 'info'
```

A `project/config` ref overrides the configured project.

## The store this row argued about

A Doppler config is a flat map that mixes secrets with ordinary configuration, which is exactly the
case the shared layer's **required** `fallback` exists for.

Fail-closed is wrong here and fails in a way that does not look like a security control: wrapping
`LOG_LEVEL` makes `config.LOG_LEVEL === 'debug'` permanently false and `if (config.FEATURE_X)`
permanently true, because an instance is an object and objects are truthy. The application
misbehaves, the cause looks like a configuration bug, and nobody suspects the wrapper. Fail-open
leaves the API keys sitting beside it unwrapped. Only the caller knows which keys are which, so the
option has no default.

`DOPPLER_RESERVED_KEYS` names the three Doppler injects into every config. They are configuration
rather than secrets and are the ones most likely to be compared against a string, which is why the
example above declares them `plain` explicitly.

## Labels and metadata

The label is `project/config`. Both are names an operator chose inside Doppler and neither
identifies an account, a host or a tenancy, so the label keeps the container the secret came from
rather than reducing to the config alone, which two projects could share.

## No version

`ref.version` is `'unknown'`. The download endpoint reports no version identifier for a config, and
the rule this row works to is that a provider which reports none says so rather than inventing one:
a timestamp dressed up as a version is worse than an honest absence, because an audit trail that
looks like it can distinguish two reads and cannot is worse than one that admits it.

## Absence versus failure

`getOptional` returns null for a 404 and nothing else. A 401 is a bad token and a 403 is a token
whose scope does not cover this config, and both keep throwing, so a broken token never arrives as a
missing config.

## The token

It has to be a `SensitiveString<'credential'>`; a plain string is refused at construction. Accepting
one would be convenient and would mean the one value that unlocks every other one is the one value
not covered. It is revealed per request under this package's own reveal context, which is a child of
whatever is ambient, so an application's `auditReveal` still sees it.

## Measured behaviour

| Question | Answer | Verified on |
|---|---|---|
| What does the download endpoint return? | A flat JSON object of string values, with `format=json` | Doppler API documentation |
| Does it report a version? | No | same |
| What does an absent config answer? | 404 | same |

**Nothing in this table has been verified against a live Doppler account.** The rule this row works
to is that a fixture written from a design document tests the document rather than the provider, and
this package's fixtures come from API documentation. That is honestly a weaker footing than the
Vault, Kubernetes and SOPS packages, which each have a second tier running against a real server, and
it is the first thing to fix if this package is used in anger.

## What this does not protect against

- **The decoded payload copy.** The response body is parsed into plain strings before anything is
  wrapped, and that copy exists until collection.
- **Doppler's own error text.** `DopplerRequestError` carries the API's `messages`, which describe
  the token's scope and the config asked for rather than any value. `includeServerErrors: false`
  turns that off for a deployment that would rather have less.
- **The Doppler CLI's own injection.** An application started by `doppler run` receives its secrets
  through `process.env`, upstream of anything here. That is the configuration loaders row's problem.
- **Memory dumps and heap persistence before GC**, which is the library-wide limitation.

## License

MIT
