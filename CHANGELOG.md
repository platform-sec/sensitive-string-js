# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- A policy's `checkRevealAllowed` hook now fails closed when it answers with anything but
  `undefined`. The hook denies by throwing, and TypeScript accepts an `async` function where a
  `void`-returning one is expected, so an `async` hook that threw after its first `await` threw into
  a Promise nobody read, after `reveal()` had already returned the raw value: the authorization hook
  failed open, silently, on exactly the reads it was written to refuse. The declared return type is
  now `undefined`, which rejects the `async` form at compile time, and the raw-value gate refuses a
  Promise, or any other returned value, as a denial, on `reveal()`, `equals()`, `mask()`, every
  transform, `serialize()` and `renew()` alike. A hook written as a block that throws or returns
  nothing is unaffected; one written as an expression that returns something now fails to compile,
  which is the point.

### Added

- Added the HTTP client row: `@platform-sec/sensitive-string-http` as the shared layer, and five
  client wrappers, `@platform-sec/sensitive-string-axios`, `-got`, `-ky`, `-fetch` and `-undici`.
  This is the one integration category where the library's default is wrong for the caller's intent.
  Everywhere else redaction fails closed and a log line loses information; at the wire the intent is
  to transmit, so `` `Bearer ${token}` `` sends `Bearer [REDACTED:credential]`, nothing throws, the
  server answers 401, and the first person to debug it pastes the raw token back in.
- The wrapper owns the call rather than installing a hook. Measured, the clients disagree about which
  half of a request a hook can still reach: axios's request interceptor sees stringified headers and a
  structured body, got's `beforeRequest` sees the exact mirror image, ky's `init` does not expose the
  body at all, and `fetch` and the undici dispatcher have no hook. A hook-based design would need a
  different correctness argument per client, and would still not reach the settlement paths, which is
  where the measured damage is.
- Both settlement paths are scrubbed, driven by a plan the reveal walker records rather than by
  searching for the raw value, which would mean holding it across the settlement path. The plan holds
  a position and the value's own redacted form, never a raw value. A revealed credential survives on
  axios in `error.config.headers`, `error.config.url` and `error.toJSON()`, on got in
  `error.options.headers`, `error.options._init[n]`, `HTTPError.message` and its stack, and on ky in
  `error.request.headers` and a frozen `error.options`. The **success** path is worse than the
  rejection: `console.log(res)` after a 200 through axios or got prints the credential, and no error
  ever existed for an error handler to catch. The error tracking row does not catch any of it,
  because by then the value is a plain `string` and `containsSensitive` returns `false`.
- axios's `response.request` and got's `response.request` and `response.req` are dropped rather than
  rewritten, conditional on the request having carried a sensitive value. A Node `ClientRequest` keeps
  the outgoing header block in `_header` and in a `kOutHeaders` symbol, which no supported API
  reaches; `util.inspect` prints it out of that buffer even after the header bag has been rewritten.
  With an empty plan the client's own objects come back untouched, `request` included, so a wrapper
  can be adopted one call site at a time.
- Auth headers are descriptors, not strings. `bearer`, `basic` and `apiKey` take the instance, and the
  reveal and the encoding both happen inside the pipeline with the marker guard run on each component
  before it is encoded. That is what keeps `basic` honest, since base64 hides a marker completely, and
  it makes the template-literal footgun unreachable through the helpers.
- The marker guard scans three encodings. Literal for JSON bodies and header values; percent-encoded,
  because a query string carries `%5BREDACTED%3Acredential%5D` and axios's `params` serializer
  produces a third, partly encoded form that neither literal scan catches; and base64, off by default,
  with three needles for the three byte alignments of the `[REDACTED:` prefix. The needle list is
  built at call time from the policy registry, so a `registerPolicy` call that changes a redaction
  format does not blind it.
- `allowedHosts` refuses a redirect to a host the caller never named, and defaults to refusing
  redirects outright once a credential sits in a header outside the Fetch specification's stripping
  set. Measured, axios, got and Node's `fetch` all strip `Authorization` and `Cookie` across origins
  and all three forward `x-api-key` verbatim, because the specification names three headers and no
  others, and most providers authenticate with a name outside that set.
- `InsecureTransportError` refuses to reveal a credential into a plaintext `http://` request to a
  non-loopback host, **before** the reveal, so a request to a host that fails the check never reveals
  at all. `allowInsecureTransport: true` opts out for a sidecar or a local TLS-terminating proxy.
- `ResponseDecodeError` replaces the client's own decoder error, naming the method, the URL and the
  content type, carrying the body's byte length and none of its bytes, and chaining no `cause`. got
  propagates `JSON.parse`'s quoted body and appends the full request URL to it, so a 14-character API
  key echoed back lands whole in a string next to the endpoint that produced it. axios is not better,
  only differently wrong: it swallows the parse failure and hands back the raw body as
  `response.data`, so a raw secret becomes an ordinary string with no class, no label and no audit
  trail. Under `responseFields` the wrapper turns that silence into the same error.
- The refusal rules do not vary by environment. An earlier draft made them strict in development and
  permissive in production; a security guarantee that weakens where the secrets are real is not a
  guarantee, and it would mean the property the suite proves is not the property that runs.
- Every reveal runs under a child of the ambient context carrying `tags.sink: 'http'`,
  `tags.host`, `tags.client`, `tags.attempt` and `tags.hop`. The last two are separate because they
  answer different questions: a retry re-sends the same request to the same host, a hop sends it to a
  host the server chose, and both write the value to a socket. `allowSendToExternal` is deliberately
  not enforced, because neither default policy sets it, so enforcing it would mean choosing between
  denying every outbound request and allowing every one.
- `reveal()` is called in exactly two modules, `reveal.ts` and `auth.ts` in the shared package, and a
  source scan across all six packages keeps it that way, so the property is checkable by reading two
  files.

- Added the config and environment row: `@platform-sec/sensitive-string-env`, a loader that reads
  `process.env` and `.env` files into a classified record, and
  `@platform-sec/sensitive-string-envalid`, the one library in the row with an extension point worth
  a package. dotenv, convict and node-config get recipes in the `env` README instead: dotenv holds
  nothing to wrap after it writes, and convict and node-config both clone their trees on read, so
  for those three the integration is `wrapFlat` or `wrapTree` plus a few lines at the call site.
- `loadEnv` requires an explicit `fallback` and has no default for it. `process.env` is the most
  mixed store this library meets, and wrapping an ordinary variable does not fail loudly: an
  instance is an object and therefore always truthy, so a wrapped `DEBUG` read as `if (debug)` is
  permanently true even for an empty string, and a wrapped `PORT` is never `=== '3000'`. The name
  pack, `commonSecretNameRules`, is exported as a constant and never applied unless the caller puts
  it in the spec, for the same reason in the other direction.
- `removeFromProcessEnv` is offered and reports what it could not reach rather than implying it
  removed everything. Deleting a variable removes the copy JavaScript can see and not the copy the
  kernel made at exec time, which is the production case for Kubernetes `env:`, `docker run -e`,
  systemd `Environment=` and a CI runner injecting repository secrets. `EnvRecord.kernelCopy` names
  the variables in that position, and is the string `'unknown'` rather than an empty array where the
  check cannot run.
- `toChildEnv` reveals named variables into a child process environment under an explicit
  `RevealContext`, and refuses before returning anything if a value carries a redaction marker.
  Without it the failure is silent and late: anything assigned into an environment object is coerced
  with `String()`, so the child authenticates with the literal text `[REDACTED:credential]` and the
  first sign is an authentication failure in a process that is not the one holding the bug.
- The `envalid` validators refuse `default`, `devDefault`, `testDefault` and `choices` at
  construction, each with a message naming the replacement. The first three are assigned without
  passing through validation, so `credential({ default: 'dev' })` types as a `SensitiveString` and
  holds a raw string at run time; `choices` is compared against the parsed value, so a wrapped value
  never matches and the check is broken rather than strict.
- `cleanEnvSafe` replaces envalid's reporter rather than disabling it. All eight built-in envalid
  validators embed the raw input in their message and the default reporter prints it and calls
  `process.exit(1)`; its logger is `console.error.bind(console)` captured at import, so it cannot be
  intercepted from outside. `reporter: null` would have leaked the same value through the thrown
  error and reported only the first bad variable, so the replacement keeps the aggregate report and
  drops the messages, throwing an `EnvValidationError` that never exits the process. envalid's
  missing-variable text is the one third-party message passed through, because
  `formatSpecDescription` builds it from the caller's own `desc`, `example` and `docs`.

### Fixed

- Every redaction walk in `core` now survives an object that refuses to answer a question.
  `redactInStructure`, `safeLog`, `safeStringify`, `containsSensitive`, `sensitiveClassesIn`,
  `redactCopy` and the logger serializer each reached through operations the object controls, and
  each of them threw. The previous fix covered two duck-type property reads; these are the rest:

  | The walk did | The object controls it through |
  |---|---|
  | `Object.prototype.toString.call(obj)` | a `Symbol.toStringTag` getter |
  | `Object.getPrototypeOf(obj)`, and therefore every `instanceof` | a `getPrototypeOf` trap |
  | `'toJSON' in obj` | a `has` trap |
  | `obj.toJSON()` | the method body |
  | `Object.keys` / `Object.entries` | `ownKeys`, `getOwnPropertyDescriptor`, and every enumerable getter |
  | `String(obj)` | `toString` or `Symbol.toPrimitive` |

  A throw from a redaction is the failure mode this library exists to prevent: `logger.info({ config })`
  took down the request rather than logging a redacted line. The guarded forms all live in
  `core`'s `probe.ts`, next to the two the earlier fix added.
- The likely case is not a Proxy at all. An ordinary object with an enumerable getter that throws is
  what an ORM produces for a relation that was not loaded, and `Object.entries` invokes every one of
  them. The earlier fix was found by measuring against envalid's strict proxy, which is why it
  reached only two probes; this one was found by driving every hook a walk touches, which is the
  difference between a replay and an enumeration. `sensitive-core/src/__tests__/hostile-objects.test.ts`
  is that enumeration, and it is the suite to extend rather than the one to trust as complete.
- The answers are documented per caller rather than uniform, because a redaction walk and a leak
  detector want opposite defaults. An object that cannot be enumerated at all becomes the
  `'[Unreadable]'` marker in `redactInStructure` and `redactCopy`, which is honest where an empty
  object would claim the value had no fields. `containsSensitive` answers `true` for the same object,
  because reporting a value it could not read as clean is how a caller ships a payload believing it
  was checked. `sensitiveClassesIn` contributes no class, because there is no class to name for
  something that was never read. A property whose own getter throws reads as absent while its
  siblings still read, so one bad field no longer costs the whole object.
- `redactInStructure` no longer copies an own enumerable `toJSON` that refused into its result. It
  had been walking such an object's properties, which is right, and carrying the method along with
  them, which is not: the next serializer to touch the supposedly inert result called it and got the
  same throw. `safeStringify` was the first thing to do so.
- `UNREADABLE` is exported from `core`, because `'[Unreadable]'` now appears in redacted output and a
  caller asserting on it should not have to write the literal.
- Three winston tests changed with this, and the change is a strengthening rather than a relaxation:
  a payload whose `toJSON` throws used to scrub the whole log record to `[sensitive-format-error]`,
  and now has its own properties walked and redacted, so the record survives with its contents
  intact, its `SensitiveString` fields marked, and the canary in the thrown message discarded unread.
  The same substitution was needed in `sensitive-scrub` and `sensitive-sentry`, whose never-throw
  wrappers used the same trigger. All three now fail the walk with a *write* rather than a read: a
  prototype whose setter refuses, which `redactCopy` hits when it assigns onto the copy it made.
  That is deliberate, because no amount of read-guarding can absorb it, so the trigger will not
  evaporate the next time `core` is hardened. `sensitive-scrub` also gained the getter payload back
  as a success case, since an event carrying an unloaded ORM relation used to lose its whole
  payload to the stub.
- `util.parseEnv` can build a variable *name* out of a *value*, and the loader now drops such names
  rather than classifying them. A `.env` line with no `=` does not lose itself, it folds into the
  next line's assignment, so a credential two lines below a typo arrives under a mangled name that
  no rule anchored on `_` can match and lands in the plain half while the report says nothing was
  wrapped. A quoted value containing `=` is parsed twice and produces a second name that is a slice
  of the value. Any parsed name holding a character no exporter can set (a control character, `=`,
  or a quote) is now refused, and reported to `onLoad` as a count rather than a list, because
  listing it would disclose the value the report exists to protect.

### Added

- Fixed four defects found reviewing the eight new secrets manager providers. Three of them were
  silent, and none was reachable by reading the code: each was found by running a probe that asked
  what the package actually does rather than what it looks like it does.
- A SOPS decrypt killed for running past its timeout was reported as an ordinary decrypt failure,
  which told the operator the wrong thing to check and handed them nothing to check it with. The two
  are indistinguishable from the outside: a killed child exits with code `null` and an empty stderr,
  because it never got to write anything, so the message said "failed with exit code null" and then
  "a decrypt failure is almost always a key or configuration problem". A timeout is now its own
  failure, named as one, with the budget in the message. The Vault transport already made this
  distinction, which is what made its absence here worth looking for.
- Expanding a Kubernetes pull secret lifted its top-level keys into the Secret's key space without
  checking for a collision, so a Secret carrying a key of the same name had it silently replaced.
  Expansion now refuses rather than choosing, which is what the Infisical source already did for a
  duplicated key: whichever one won, an application would be reading a value from somewhere its
  classification never described.
- An OCI ref that carried a scheme and authority put the host and port into
  `ResolvedSecretRef.path`, which is what every error quotes and what every load event carries to
  the audit sink. The label was correctly reduced to the secret name and the resolved path was not,
  so the label rule was doing its job and the field beside it was undoing it. Such a ref is now
  refused, matching the Vault package, which refuses the same shape for the same reason. OCI was the
  only one of the nine providers whose resolved path was not already reduced.
- `pnpm lint` and `pnpm lint:fix` set a 6 GB Node heap, because they need it. Type-aware linting
  follows imports into the vendor type declarations, and the new providers pull in the AWS SDK, the
  Kubernetes client and the generated GCP protobuf definitions, so on a 10 GB machine the run was
  OOM-killed partway through. That is worth recording rather than only fixing: a killed lint reports
  `Killed` on stdout, and a wrapper reading the exit code of a pipeline rather than of ESLint itself
  sees success. This one did, and reported a passing lint that had not finished.
- `jwtExpiry` trims its input, so a Kubernetes token written into a Secret with `--from-file` carries
  the file's trailing newline harmlessly. The mounted source trimmed and the API source did not, and
  which of the two remembered is not a property worth having.

- Added the eight remaining secrets manager providers, which completes the row:
  `@platform-sec/sensitive-string-aws-secrets`, `-azure-keyvault`, `-gcp-secrets`, `-oci-vault`,
  `-k8s`, `-sops`, `-doppler` and `-infisical`. Every one of them is an `index.ts`, a `source.ts` and
  a wire-shape module over the shared layer, which is what the shared layer was for.
- Only the AWS package imports its vendor SDK at run time, because AWS v3 dispatches through command
  objects that have to be constructed. Azure, GCP, OCI and Kubernetes declare theirs as a types-only
  peer: the client is injected and the calls are ordinary methods, so the built output contains no
  vendor import while the fixtures are still typed as the SDK's own response types, which is what
  makes a field the package reads have to exist on the real response. Doppler and Infisical have no
  SDK and no third-party runtime dependency at all: one endpoint over `fetch` each.
- Three of the new packages have a second test tier that runs against a real server, each
  self-skipping on an environment variable and wired into CI as an informational matrix job:
  Kubernetes against k3s, SOPS against the real binary, and AWS against a Secrets Manager emulator.
  The rule this row now works to is that a fixture written from a design document tests the document,
  and the live tiers are what enforce it. They earned themselves immediately, twice.
- Measured on Kubernetes v1.34.1: `kubectl apply` of a Secret written with `stringData` puts the
  secret into the `last-applied-configuration` annotation **unencoded**, where the Secret's own
  `data` is at least base64. The design that preceded the package said the annotation holds `data`;
  applying with `stringData` is the common way people write a Secret by hand, and that is the worse
  case. The annotation strip was already unconditional and whole-map, which is what made this a
  documentation correction rather than a fix.
- Measured on sops 3.13.3: an absent document produces `cannot operate on non-existent file` and
  exit code 100. The package had been matching on `no such file or directory`, which is what its own
  stand-in binary printed and not what sops says, so `getOptional` threw for every absent document
  instead of returning null. The absence check is now the filesystem's rather than the binary's
  message, and the stand-in binary prints what the real one prints.
- Measured on sops 3.13.3, which settles the open question behind `includeStderr` defaulting to true:
  on the wrong-identity, tampered-ciphertext and not-a-SOPS-document paths, stderr carries no
  plaintext. It does carry the recipients' public age keys and the local paths sops probed for
  identities, which on a developer machine includes a home directory, and that is now in the README
  as the reason a deployment might still turn it off.
- Measured on `@aws-sdk/client-secrets-manager` 3.1126.0: the SDK's own logger does redact
  `SecretString`, rendering it as `***SensitiveInformation***`. It logs the ARN, which carries the
  account id, on the same line, and it says nothing about the application's own logging or about a
  response object that reaches an error tracker. The claim in the design is now measured rather than
  assumed.
- `getAll` no longer requires the keys named in its `fields` to be present. `getAll` discovers a key
  set and `getJson` is the surface where the caller knows it, so requiring presence belongs to the
  second. The Kubernetes type specs are what surfaced it: the service-account-token spec classifies
  `service-ca.crt`, which only some clusters mount, and the pull secret spec classifies both the
  expanded and the unexpanded shape, of which exactly one is ever present. Both would have failed
  every load.

- Fixed four defects in the secrets manager packages before release, two of them security-relevant.
  None was findable by the unit suite as it stood, and the two that mattered most came from test data
  written out of a design document rather than out of a real provider.
- The shared layer wrapped multi-value payloads by dot path through `wrapSensitiveByPath`, which
  reads `a.b` as a path into a nested object. A flat key containing a dot therefore matched nothing
  and was left unwrapped, silently, with no error: a `getAll` on a Kubernetes-shaped secret returned
  `tls.key` as an ordinary string in the plain map. Kubernetes Secret keys are routinely `tls.key`,
  `ca.crt` and `.dockerconfigjson`, so this was the common case for that source rather than an edge
  one, and under-protection is the failure the layer exists to prevent. Wrapping now happens at the
  leaf of the classification walk, which also removes the deep clone that helper made, and a payload
  where a dotted key and a nested one address the same name is refused as ambiguous.
- The Vault package bound a KV v1 read's `lease_duration` as a deadline. Measured on Vault 1.21.4 and
  OpenBao 2.6.2, a KV v1 read reports 2764800, the mount's default TTL, and not the zero a KV v2 read
  reports and the fixtures had recorded. A valid credential would have started throwing 32 days after
  it was loaded with nothing having revoked it. A KV read now binds no deadline on either engine
  version, the reported duration goes on `metadata` where nothing enforces it, and `lease_id` rather
  than the duration is what says a lease exists.
- A dynamic lease renewal passed Vault's new total remaining lifetime to core's `renew`, which adds
  to what is left rather than replacing it, so a credential renewed an hour before it lapsed outlived
  its lease by that hour. It now extends by the difference, which is the fail-closed direction.
- A KV v1 read echoed the requested version back as a resolved one, and KV v1 has no versions. A read
  now reports `unversioned`, and pinning a version against a KV v1 mount is refused rather than
  silently served the current value. The write path's read-back reads the current version rather than
  pinning the one it wrote, which is both a stronger guarantee and what makes it work against a store
  that overwrites in place.
- Added `@platform-sec/sensitive-string-secrets` and `@platform-sec/sensitive-string-vault`, the
  shared layer and the first provider of the secrets manager row of roadmap 3.7. A secret arriving
  from a secrets manager is a `SensitiveString` from the moment the response is destructured, the
  provider response object never leaves the provider package, the provider's own name for the secret
  becomes the label, and a lease becomes a deadline bound to the value.
- The decode guard is the reason the shared layer exists. `JSON.parse` puts its input into the
  `SyntaxError` message: measured on Node 22.15.0, an input of 20 characters or fewer is echoed
  whole and a longer one discloses its first 10 characters, while a truncated JSON document reports
  only a position and is safe. So the failure mode that leaks is the one where the secret is not
  JSON at all, which is exactly what happens when a JSON read is called on a secret holding a bare
  API key, and a 20-character key is a common length. Every decoder parses inside a guard that
  discards the original error and never chains it through `cause`, since every error reporter
  serializes the cause chain. A sweep case pins the V8 behaviour as well as the fix, so the
  measurement fails rather than rots if a future Node stops leaking there.
- `getAll` requires an explicit `fallback` and has no default, which is the one place in this design
  where no default is better than either. Fail-closed breaks a store that mixes configuration with
  secrets, and breaks it in a way that does not look like a security control: a wrapped `LOG_LEVEL`
  makes `config.LOG_LEVEL === 'debug'` permanently false and `if (config.FEATURE_X)` permanently
  true, because an instance is an object and objects are truthy. Fail-open under-protects a
  Kubernetes Secret or a Vault KV path, where everything is secret by construction. Only the caller
  knows which kind of store it is.
- The write path is a separate entry point, `@platform-sec/sensitive-string-secrets/write`, and it
  is where the roadmap's claim that this row transmits nothing turned out to be false. A write is a
  transmit, and a `SensitiveString` handed to a provider's write call stringifies to
  `[REDACTED:credential]` and is stored under that value: the write succeeds, the provider reports
  success, and every later reader receives the marker as its database password. `put` and `putJson`
  reveal under a required `RevealContext`, refuse outgoing bytes containing `[REDACTED:` before any
  transport call, and read the new version back with `equals()` by default.
- `core` gained `ClassificationSpec`, `FieldClass` and `compileClassification`, which the config and
  environment row of 3.7 needs as well, so the precedence rule is written once rather than twice.
  Patterns are compiled once per source and are stripped of `g` and `y`, because both make a
  `RegExp` stateful through `lastIndex` and a global pattern tested twice answers `true` then
  `false` for the same key. `SensitiveFieldOptions` gained `options`, so a path-based wrap can bind
  a provider's deadline to every field it wrapped rather than leaving it in metadata that nothing
  enforces.
- `vault` covers KV v1 and v2, dynamic secret leases, response wrapping, token renewal, and OpenBao
  as a flavor rather than a second package. `lease_duration` converts to milliseconds in one named
  function with a test that pins the factor, and `lease_duration: 0` means no lease rather than an
  already-expired value, because `ttl: 0` in core means exactly the opposite.
- Two rows of the OpenBao compatibility table moved when they were measured against real servers,
  Vault 1.21.4 Community Edition and OpenBao 2.6.2 in dev-mode containers. `X-Bao-Token` is not an
  accepted alias: OpenBao answers it with 403, so `X-Vault-Token` is the compatible header because
  it is the only one either server accepts. And the silent wrong-secret risk from a stray
  `X-Vault-Namespace` is not OpenBao's: OpenBao turns the read's 200 into a 404, so a caller
  notices, while Vault Community Edition accepts the header, ignores it, and serves the root
  namespace with a 200. The OpenBao case throws at construction; the Vault Community case is
  documented, because telling Community from Enterprise would mean letting a server response decide
  how the client behaves, which is what the flavor flag exists to avoid. A `vault-compat` CI job
  runs the live suite against both containers so the table's version column keeps meaning something.
- Added `@platform-sec/sensitive-string-scrub` and `@platform-sec/sensitive-string-sentry`, the
  error tracking row of roadmap 3.7. The roadmap described this as "one `beforeSend` hook running
  `redactInStructure`", and all three nouns were wrong. Measured on Node 22.15.0 against
  `@sentry/node` 10.73.0: `beforeSend` receives an event the SDK has already normalized through its
  JSON form, so every `SensitiveString` in it is a string by then and structural redaction there is a
  no-op; `redactInStructure` replaces the second visit to a shared reference with `'[Circular]'`,
  which corrupts an event that legitimately holds one object at two paths; and the leak is not
  unredacted instances at all, because a wrapped value is already safe on every path tested. The
  leak is the raw strings nobody wrapped, sitting beside the wrapped ones: at stock defaults, with no
  `sendDefaultPii` and no `dataCollection`, one inbound request puts `request.headers.authorization`,
  `request.headers.cookie`, `request.cookies`, `request.url` and `request.query_string` into the
  outgoing event verbatim.
- `scrub` is the shared layer, with no third-party runtime dependencies. It runs two walks, one per
  stage, with the report accumulated during the second rather than computed by a third: structural
  redaction through `redactCopy`, which keeps prototypes and shared references and replaces a
  `serialize()` result with the marker of the class it names, and then a key and path denylist over
  the copy. `DEFAULT_DENY_KEYS` is the union of `rollbar` 3.1.0's three key-shaped default lists,
  which a test asserts is still a superset of what the installed `rollbar` ships, plus the
  credential-bearing names those lists omit. Matching is on key names and paths and never on values.
  A denied value is replaced rather than deleted, and `allowKeys` requires a reason string, because
  taking a key off the default list is the one operation here that makes it leak more. `urlKeys`
  replaces the denied query parameters of a URL and keeps the route, since deleting the URL removes
  most of an error report's value. A value structural redaction already replaced keeps its marker
  rather than being censored over, because the marker names the class and is equally safe.
- The marker rule inverts here. 3.7 says an integration that transmits throws if the outgoing bytes
  contain `[REDACTED:`; an error tracker is a sink rather than a wire, so the marker is the desired
  output and its absence is the failure. A marker in *captured* data is instead evidence that another
  integration failed, and is reported through the `sensitive.marker_seen` tag rather than thrown on,
  since throwing would suppress the report of the incident the marker is evidence of.
- No hook body throws. Measured: a `beforeSend` that throws makes Sentry drop the original event and
  send a replacement describing the scrubber's own exception, so the error the user needed is gone
  and the alert names the wrong thing. On an internal failure the payload becomes a stub carrying the
  exception type, the grouping data the vendor already computed, and a `sensitive.scrub_failed` tag,
  and `onScrub` is called with `failed: true`. Only two independent failures, a scrub that throws and
  a stub that throws, drop a payload.
- `sentry` is an options wrapper rather than an integration, which the measurements force. An
  integration cannot reach `beforeBreadcrumb`, a client option, and an integration's `processEvent`
  runs in registration order: one listed before `extraErrorDataIntegration()` never sees the
  `contexts.<ErrorName>` it writes, which is where a custom property on a thrown error lands with raw
  values intact. `withSensitiveScrubbing` composes all six `before*` hooks at `init` and appends an
  integration whose `setup()` registers a scope event processor, which the SDK runs after every
  integration's `processEvent` regardless of array order. A caller's hook is composed rather than
  replaced and runs after the scrubber on the already-scrubbed payload; one returning `null` still
  drops the payload; one that throws does not lose the event. The wrapper is idempotent and does not
  modify the options object it was given, and it refuses `sendDefaultPii: true` rather than scrubbing
  harder, because that option enables every collection category and is deprecated in v10.
- Two rows of the hook map were measured that the design had recorded as unmeasured and assumed:
  `beforeSendLog` and `beforeSendMetric` both hand over live `SensitiveString` instances, while
  `beforeSendTransaction` and `beforeSendSpan` do not. Structural redaction runs at every seam
  regardless, because "already normalized" is a property of one version rather than a documented
  contract. `beforeSend` runs as a quiet backstop: it scrubs without reporting, so one payload still
  produces one report, and with marker counting off, since by then the earlier pass has written a
  marker everywhere a wrapped value stood.
- Added `recommendedDataCollection`, an object to spread into `Sentry.init` rather than a default
  this package applies. `sendDefaultPii` defaults to `false` and headers, cookies and query strings
  were still captured verbatim, because `dataCollection`'s per-category defaults are what governs
  collection. The object turns off `cookies`, `httpBodies`, `databaseQueryData` and `genAI`, and the
  README explains each. Silently changing what an error tracker collects is too large a behavioural
  change to make from inside a scrubbing package.
- Added a type-level seam check. `COVERED_HOOKS` is asserted against
  `Extract<keyof NodeOptions, 'before${string}'>` in both directions, so a seventh hook in a future
  SDK release fails compilation with the new hook's name in the failure, and a stale name here fails
  it from the other side. Verified by removing `beforeSendMetric` and watching the check name it.
- Added a canary sweep for each package. Every position an SDK captures gets a canary, a real error
  is driven through the real SDK to a capturing transport, and the canary is asserted absent from the
  whole outgoing envelope. A companion case runs the same positions with no scrubbing and requires
  every one of them to leak, so a fixture that stopped exercising anything fails rather than passing
  quietly. Nothing in either suite mocks the SDK. Alongside them are five pinning tests recording the
  vendor behaviour the design depends on, and an import-surface test asserting that shipped source
  imports only `SensitiveString`, `redactCopy`, `containsSensitive`, `sensitiveClassesIn` and
  `SensitivityClass` from core, since a scrubbing package that reveals has inverted its own purpose.

### Fixed

- Fixed a leak in the tracing seams found by reviewing the first cut. One `http.get` to
  `/pay?token=SECRET&page=2` puts the token into five span attributes on `@sentry/node` 10.73.0,
  `url.full`, `http.url`, `http.target`, `http.query` and `url.query`, and the URL key list carried
  only the second, so the other four left the process with the token in them. The list is now the
  measured set, and a test drives a real outbound request through the SDK's own HTTP instrumentation
  and asserts the canary reaches no attribute, with a companion case requiring it to leak when the
  scrubbing is removed and a pinning test naming the attributes so a rename is diagnosable rather
  than just red. The event-shaped canary sweep could not have caught this: a span is assembled by the
  SDK's instrumentation, not by anything an application writes, so a fixture built by hand never sees
  what one carries.
- `scrubUrl` now handles a relative URL. `new URL()` refuses `/pay?token=SECRET&page=2`, and handing
  it to `URLSearchParams` yields the keys `['/pay?token', 'page']`, so nothing matched and the string
  was kept whole. That is the shape a span's `http.target` holds. It is resolved against a base that
  is discarded, re-emitted from the path onwards, and only when a denied parameter actually matched:
  an arbitrary string also resolves against a base and would otherwise come back percent-encoded.
  Nothing is rewritten purely to normalize it, so a subject with nothing denied in it comes back
  byte-identical.
- The failure behaviour is now per payload kind. `buildEventStub` was used for all of them, which
  produces a span with no `span_id`, a log with no body and a transaction with no trace context.
  `beforeSend` and `beforeBreadcrumb` keep their stubs, because losing an error or a position in a
  timeline loses information; `beforeSendTransaction`, `beforeSendLog` and `beforeSendMetric` now
  drop, which all three accept, because a malformed payload is worse than an absent one and losing
  one is what sampling already does.
- `beforeSendSpan` never answers `null`. Measured: the SDK logs "Returning null from
  `beforeSendSpan` is disallowed" and then pushes the **original, unscrubbed span** into the
  envelope. Both paths that would have returned one are closed, the scrub-and-stub double failure
  with a content-emptied span stub, and a caller's own null with the scrubbed span. A caller's intent
  to drop is not honoured, because the SDK does not offer it, but it no longer becomes a raw send.
- Installing the package no longer disables span streaming. `spanStreamingIntegration` resets
  `traceLifecycle` to `'static'` when it finds a `beforeSendSpan` the SDK did not mark, and this
  package installs one unconditionally. Its hook now carries the marker, and deliberately does not
  when the caller supplied an unmarked hook of their own, so the SDK's warning still reaches the
  person it is aimed at.
- `composeAfter` now catches a rejected promise from a caller's hook, not only a synchronous throw.
  `beforeSend` may return a promise, so a rejection reached the SDK as a dropped payload, which is
  the outcome the never-throw contract exists to prevent.
- A caller taking a key off the denylist that a vendor package had added no longer fails at init.
  `mergeScrubPolicy` treats it as the override it is, rather than handing the caller a
  `ScrubPolicyError` naming a `denyKeys` list they never wrote. A caller who writes the same key into
  both of their own lists still gets the error, which is the contradiction it is for.

### Changed

- Added a `typecheck` script, `tsc --noEmit` over the whole repository including tests, and a CI step
  that runs it. The type-level seam checks live in `.test-d.ts` files that `vitest` does not collect
  and a package build excludes, so without this they would have compiled nowhere.

- Added `redactCopy()`, the walk a response body needs before a serializer other than
  `JSON.stringify` sees it. It copies the structure with every `SensitiveString` replaced by its
  redaction and every `serialize()` result, recognised by its `__sensitive: true` marker, replaced by
  the redaction of the class it names, keeping each object's prototype so an entity `toJSON()` still
  runs, preserving shared references, and passing streams, `Buffer`, `Date`, `Map`, `Set`, `RegExp`,
  and `URL` through by reference. `redactInStructure()` remains the walk for log lines, where a
  plain-object copy is what a log wants. The NestJS `SensitiveResponseInterceptor` now delegates to
  it, which is how that interceptor gained the serialized-value case.
- Added `@platform-sec/sensitive-string-fastify`, the Fastify integration. `sensitiveKeyword` is an
  Ajv keyword: a `sensitive: { klass, label }` annotation on a string property in a body,
  querystring, or params schema replaces that property with a `SensitiveString` during validation,
  after the property's own `type`, `minLength`, and `format` checks have run on the raw string, and it
  reaches nested objects, array items, and `$ref` schemas added with `fastify.addSchema`. It goes into
  `Fastify({ ajv: { customOptions: { keywords: [sensitiveKeyword] } } })`, because Ajv is built with
  the instance. `sensitivePlugin` covers what a schema cannot: a `body` field map through core's
  `wrapSensitiveByPath` for routes without one, scoped by Fastify's own encapsulation and merged with
  a route's `config.sensitive.body`; `headers`, which puts wrapped copies on
  `request.sensitive.headers` and leaves `request.headers` byte-identical; `context`, a callback-style
  hook whose `AsyncLocalStorage` scope covers every later hook, the handler, its `await`
  continuations, and the error handler; and `responseFilter`, a `preSerialization` walk through
  `redactCopy` for the serialized values and entity instances neither of Fastify's serializers
  redacts on its own. A headers schema using the keyword is refused at route registration, because
  there the keyword would replace the value in the raw Node headers object that Fastify itself reads
  as strings, and the field map is gated to `application/json` and
  `application/x-www-form-urlencoded` by default, widened with `contentTypes`, because the clone
  inside `wrapSensitiveByPath` flattens a `Buffer` into a numeric-keyed object and a `Map` or `Set`
  into `{}`. The keyword must also stay out of a union branch that can fail after it has run: Ajv
  does not undo a `modifying` write, so a sibling branch requiring `type: 'string'` then sees an
  object. Fastify 5 only.
- Added `@platform-sec/sensitive-string-express`, the Express integration. `sensitiveBody()` wraps
  configured `req.body` fields through core's `wrapSensitiveByPath`, scoped by the mount path;
  `sensitiveHeaders()` puts wrapped copies on `req.sensitive.headers` and leaves `req.headers`
  byte-identical, so `req.get()`, CORS, and authentication middleware keep working;
  `sensitiveContext()` establishes the reveal context for every later middleware, the handler, its
  `await` continuations, and any error handler; `sensitiveResponseFilter()` patches `res.json` and
  `res.jsonp` to run `redactCopy` over the body, which covers serialized values and entity instances
  that `toJSON()` cannot; and `stripParseErrorBody()` removes the raw request body that body-parser
  attaches to the 400 it raises for a malformed payload. Field maps are validated when the
  middleware is constructed, so a typo is a startup failure rather than a field that quietly stays a
  plain string. Express 4.21+ and 5 are both supported, with the suite running on 5 and a smoke test
  of the whole stack on 4.
- Added `@platform-sec/sensitive-string-decorators`, the framework-agnostic Stage 3 decorators.
  `@Sensitive` wraps every value an auto-accessor field receives, including the field initializer
  and a value hydrated onto the instance through an untyped path, and refuses one whose class is
  less restrictive than the field's. `@WithRevealContext` runs a method inside a named reveal
  context, nesting it over the ambient one so an outer audit sink keeps receiving records, and
  covers generators and async generators by wrapping the iterator, since their bodies resume after
  the context would otherwise have closed. Stage 3 only: NestJS applications get the same two names
  from the NestJS package. Note that an `accessor` field is a prototype getter and setter pair
  rather than an own property, so `JSON.stringify` omits it instead of redacting it; declare
  `toJSON()` where the serialized shape matters.
- Added `@platform-sec/sensitive-string-nestjs`, the NestJS integration. `@Sensitive` marks DTO
  properties, `SensitiveTransformPipe` wraps them after `ValidationPipe` has validated the plain
  strings, `SensitiveContextInterceptor` and `@WithRevealContext` establish the reveal context for
  the request, `SensitiveResponseInterceptor` redacts response bodies, serialized values included, before a
  serializer sees them,
  and `@SensitiveHeader`, `@SensitiveParam`, and `@SensitiveQuery` wrap sensitive data that arrives
  outside a DTO. The package ships legacy-signature decorators, since NestJS cannot run the Stage 3
  ones the decorators package targets.
- Added `sensitiveFormat()`, a winston format that redacts every `SensitiveString` in a log record
  before a terminal format or a transport serializes it. Install it at the front of
  `format.combine(...)`; in a later position the output string already exists and the format emits a
  process warning saying so. It adds no runtime dependency, because winston's format contract is
  satisfied structurally.
- Added `dropClasses` to `sensitiveFormat()`, which discards a whole record that carries a given
  sensitivity class rather than redacting it, so a transport can refuse credential-bearing records
  outright. Its companion `stampClasses` records what a record carried before redaction erased the
  evidence, which is what lets a transport-level check work behind a logger-level redaction.
- Added `sensitiveClassesIn()`, which collects the sensitivity classes present anywhere in a
  structure, where `containsSensitive()` only answers yes or no.
- Added protected string transformations for trimming, case conversion, padding, slicing,
  splitting, replacement, and character access.
- Added policy-controlled partial queries for prefix, suffix, containment, and index checks.
- Added protected regular-expression matching, named-group extraction, and match iteration.
- Added policy-controlled `test()` and `search()` regex queries and the anchored `patterns.email`
  helper.
- Added the `sensitiveTemplate` tagged template and its `st` alias for building protected values
  from template literals, with optional reveal context, label, and class.
- Added `mask()` for partial masking, with positional `showFirst` / `showLast` options and the
  `email`, `phone`, `card`, `ssn`, `uuid`, and `custom` strategies.
- Added the `minMasked` floor, which defaults to 4 for `sensitive` and 8 for `credential`.
- Added `RevealDetails` to the `auditReveal` callback and to `withAuditedReveals`, so an audit sink
  can tell a full reveal from a mask and see the options that produced it.
- Added expiration: the `ttl`, `expiresAt`, `allowRenewal`, `maxRenewals`, and `onExpire`
  construction options, the `expiresAt` and `renewalCount` properties, and the `isExpired()`,
  `ttlRemaining()`, `isRenewable()`, and `renew()` methods.
- Added the `ExpiredSensitiveValueError` and `RenewalNotAllowedError` error classes, so a caller can
  tell a lapsed deadline from a policy denial and decide whether to fetch a fresh secret.
- Added the `allowRenewal`, `defaultTtl`, `maxTtl`, and `requireExpiration` policy fields, which set
  and cap expiration for a whole sensitivity class.
- Added `expiresAt` to the serialized wire format, and a `renew` audit record carrying both
  deadlines and the renewal count.
- Added the `@platform-sec/sensitive-string-testing` package, which depends on no test framework
  and works with Vitest and Jest alike.
- Added `createTestSecret`, which builds unique, conspicuous canary values and accepts every
  `SensitiveStringOptions` field, plus the `createExpiredSecret` and `createExpiringSecret`
  factories for the two shapes tests need most.
- Added the `expectNotLeaked` and `expectRedacted` assertions, and the `LeakageDetectedError` they
  throw, which names the class, the label, and the path a value was found at.
- Added the `sensitiveMatchers` object and `setupSensitiveMatchers`, providing
  `toBeSensitiveString`, `toHaveSensitivityClass`, `toHaveLabel`, `toRevealAs`, `toBeExpired`, and
  `toContainSensitive`, usable asymmetrically as well, with a ready-made Vitest type augmentation at
  the `/vitest` entry point.
- Added `mockRevealContext` and `createMockAuditLog` for asserting on audit behavior. Both take a
  spy factory such as `vi.fn` rather than detecting a framework at runtime.
- Added `collectFragments`, `findRawValue`, and `joinFragments`, the leak-scanning primitives the
  assertions are built on, for a check the package does not already provide.
- Added `UnreadableSecretError`, raised when a check could not read the value it was asked to look
  for, so a refused reveal is never mistaken for a clean result.
- Added the `@platform-sec/eslint-plugin-sensitive-string` package, which has no runtime
  dependencies and works under ESLint 8.40 or newer, in flat and eslintrc configs alike.
- Added `no-log-reveal`, which reports a revealed or serialized value reaching a logger, at any
  depth inside an argument, and recognises a logger reached through `this`, through a request
  object, or through a builder call.
- Added `no-credential-equality`, which reports `===`, `==`, `!==` and `!=` on a revealed value, and
  a `switch` on one, with a suggestion rewriting the comparison to `.equals()` that carries any
  reveal context into the second parameter.
- Added `no-network-sensitive`, which reports an unaudited reveal in an HTTP request and allows one
  that names its purpose, with `allowWithContext: false` to forbid both.
- Added `explicit-class`, which reports `new SensitiveString(v)` with no sensitivity class and
  suggests each class.
- Added `require-reveal-context`, which reports a `reveal()` with no context argument and no
  enclosing `withRevealContext()`, with `requireReason: true` to also require the `reason` field.
- Added the `recommended` and `strict` presets in flat form, and `legacy-recommended` and
  `legacy-strict` in eslintrc form, built from one list of rule settings so the two cannot drift.
- Every rule that asks for an argument treats an explicit `undefined` as the absence of one, so
  `reveal(undefined)` neither silences `no-network-sensitive` nor satisfies `require-reveal-context`,
  and `new SensitiveString(v, undefined)` still reports a missing class.
- Added `sensitiveSerializer` and `createSensitiveSerializer`, a snapshot serializer that renders a
  `SensitiveString` as `SensitiveString<class:label>`, with optional `{length}` and `{expired}`
  fields and a custom `format`. It is available from the package root and, for a runner that loads
  a serializer by path, from the `/serializer` entry point.

- Added collection helpers to the `zod` package: `zSensitiveArray`, `zCredentialArray`,
  `zSensitiveStringArray`, `zSensitiveRecord`, `zCredentialRecord`, and `zSensitiveStringRecord`.
  Each wraps a per-element schema in a plain `z.array` or `z.record`, so the collection combinators
  still apply and a failing element reports its own index or key.
- Added `refineSensitive`, both as a method on every schema the `zod` package builds and as a
  standalone function, for a refinement whose predicate needs the raw string. It reads through
  `reveal()`, so the ambient context authorizes it and its `auditReveal` hook records it. It
  manufactures no context of its own: a policy that refuses a context-free reveal refuses this one
  too. An async predicate works under `parseAsync` and is refused, not skipped, under `parse`.
- Added `zSensitivePreprocess`, `zCredentialPreprocess`, and `zSensitiveStringPreprocess`, which
  normalize the input, validate it, then wrap it. Trimming a wrapped value would mean revealing it;
  doing it during the parse keeps the whole sequence on the raw string. Steps come from a
  declarative option set, a function, or a list of functions.
- Added `zSensitiveDefault`, which produces its fallback as a raw string and wraps it, so a
  generated default is classified the same way a parsed one is. `null` and `''` do not trigger it.
- Added `zConditionalSensitive`, which builds a discriminated union whose value field is classified
  by a sibling field, so an unknown discriminator is rejected before the value is looked at. It
  refuses a discriminator and a value field with the same name, which would otherwise collapse into
  one object key and leave the schema classifying nothing.
- Added `sensitiveErrorMap`, `installSensitiveErrorMap`, `redactZodError`, `redactZodIssues`,
  `sensitiveParse`, `sensitiveSafeParse`, and `sensitiveSafeParseAsync`, which keep the input out of
  validation errors. The parse helpers treat an explicit `errorMap: undefined` as no error map
  rather than as one that disables the default.

### Changed

- A policy's `checkRevealAllowed` now receives the value being read and what is being authorized,
  as `(ctx, value, access)`, where `access` is `'compare'` for `equals()`, `'expose'` for every
  operation that hands the raw value or part of it to the caller, and `'renew'` for a deadline
  extension. It had received the context alone, so a policy could refuse a read only on the class
  and the context, never on the label or the deadline of the value in front of it, while the
  `auditReveal` call three lines below it in the same gate already got the instance. Reads that
  only feed redaction or documented metadata, such as `toString()` and `length`, still never reach
  a policy. The parameters are additive: a hook written against the context-only form keeps
  working. It must not read the value it is handed, through `reveal()`, `equals()` or `mask()`,
  because the gate is not reentrant and the read would recurse until the stack is exhausted.
- `new SensitiveString()` throws a `TypeError` for a value that is not a string, naming the kind of
  value and never its content. It accepted anything: a number redacted like a string and then threw
  inside `equals()`, and an instance wrapped a second time revealed the inner instance rather than
  the value. Every derived value goes through the same check, so a `map()` callback that returns a
  non-string is refused as well. `fromOptional()` still maps `null`, `undefined`, and the empty
  string to `null`.
- The release workflow now reads the packages to release from `packages/` rather than from a
  hardcoded pair of steps per package. It offers all six in its dropdown, skips a package marked
  `private`, and carries `{dir, name, version}` through one output that every later step loops
  over. `decorators`, `eslint-plugin`, `nestjs`, and `testing` could not be released before this,
  and `all` released only `core` and `zod` while reporting success. Tags take the package's npm
  name, so `@platform-sec/eslint-plugin-sensitive-string` no longer has to match its directory.
  Workflow inputs reach the scripts through the environment rather than `${{ }}` interpolation.

### Fixed

- The redaction walks no longer fail when an object refuses a property read. `redactInStructure()`,
  `safeLog()`, `safeStringify()`, `containsSensitive()`, `sensitiveClassesIn()`, and `redactCopy()`
  each ask an arbitrary object a duck-type question or two: whether it carries the
  `__sensitive: true` marker that a `serialize()` result has, and in `redactCopy()` whether it has a
  `pipe` method and is therefore a stream. Both were plain property reads, and reading an absent
  property is not universally safe, because a Proxy may throw for an unknown name rather than
  answering `undefined`. envalid's `cleanEnv()` result is such a Proxy, so logging a validated
  configuration object through any of these helpers raised
  `ReferenceError: [envalid] Env var not found: __sensitive` instead of redacting anything, and it
  did so when the object was merely nested inside the record being logged, which is how it is
  normally logged. The probes now go through one guarded read that treats a refusal as absence, so
  the walk descends into the object and redacts every `SensitiveString` it holds as it would for any
  other object. Nothing that answers the question behaves differently.

- `safeStringify()` returns the string its signature promises. It forwarded `JSON.stringify`'s
  `undefined`, which is what that function returns for a value JSON cannot represent: `undefined`
  itself, a function, a class constructor, a symbol, or a root dropped by a caller's replacer.
  TypeScript's own lib declares `JSON.stringify` as returning `string`, so nothing flagged the
  mismatch and a caller who believed the declaration failed on the result rather than at the call.
  Those values now serialize as `'null'`, which is what `JSON.stringify` already substitutes for
  them in array position, so the return stays parseable. Deliberately not `String()`: a function's
  string form is its source text, which would put a static field's initializer into the output this
  function exists to keep safe.
- `safeStringify()` no longer throws on a `BigInt`. `JSON.stringify` rejects one with a `TypeError`
  rather than skipping it, so a single `id: 1n` anywhere in a payload took down the logging call
  that was meant to be the safe one. A `BigInt` now serializes as its decimal string, which is
  lossless where `Number()` would silently round anything past 2^53. A caller's `replacer` still
  runs first and sees the real value, so it can choose its own representation, and it keeps
  receiving the holder object as `this`.
- `zSensitiveDeserialize` reports a class mismatch, an unregistered class, and a malformed payload
  as Zod issues instead of throwing out of the transform. A throw there escaped `safeParse`, so a
  caller who chose the non-throwing API got an exception anyway, from the one schema whose whole job
  is handling a payload from another service.
- Corrected the `exports` map in all three packages. Every one declared a `require` condition
  pointing at a `dist/*.cjs` file that `tsc` never emits, so `require()` of any package failed with
  `MODULE_NOT_FOUND`, and importing a package that depends on another failed the same way through
  the dependency. The build emits CommonJS `.js`, which one `default` condition serves for both
  `require` and `import`.
- Added `pnpm check:packaging`, which loads every built package by its own name through both
  `require` and `import` and checks that each path a manifest names exists and survives packing. The
  unit suite imports by relative path, so nothing exercised a manifest and three broken ones went
  unnoticed. It runs in CI after the build.

### Security

- `redactInStructure()`, and with it `safeLog()`, `safeStringify()`, `createSensitiveSerializer()`,
  and the winston format, replace a `serialize()` result with the redaction of the class it names,
  or `'[REDACTED]'` for a class that is not registered. The serialized form is a plain object holding
  the raw value, so it passed through every log-path helper untouched and `JSON.stringify` emitted
  it; it was the one shape `toJSON()` could not catch. `containsSensitive()` now reports it and
  `sensitiveClassesIn()` counts the class it names, so `dropClasses` in the winston format refuses a
  record carrying a serialized credential as it refuses one carrying the instance.
- `redactInStructure()` walks the JSON form of a plain object that carries its own `toJSON`, as it
  already did for class instances. The plain-object copy kept the function and left it for
  `JSON.stringify` to call later, on a form the walk had never seen.
- Zod puts the input into the issue for four codes: `invalid_enum_value` and `invalid_literal` in
  `received`, `unrecognized_keys` in `keys`, and `custom` in `params`, with `invalid_union` nesting
  any of them one level down. An error map cannot reach those fields, only the message, so the
  `zod` package fixes both halves. `sensitiveSafeParse` applies the map and redacts the issues;
  `installSensitiveErrorMap` covers schemas that never pass through it. The map is not installed on
  import, because a library that rewrites a process's global Zod configuration behind the
  application's back is worse than one that asks for a line of setup.
- A sweep runs every schema factory in the `zod` package against a canary in every position it
  accepts and scans the message, the issue objects, and both formatted shapes of the error. A
  factory added to the package without an entry in the sweep fails the suite.
- The leak walk has no depth limit. A limit stops in the middle of a structure the walk could
  otherwise finish, and a leak below the cut reads as no leak at all; the walk uses an explicit
  stack so depth costs heap rather than call frames. A node budget bounds a hostile target that
  fabricates work without end.
- A reveal refused by a deadline or a policy raises `UnreadableSecretError` naming the value and the
  cause, rather than surfacing an unrelated error from inside an assertion about output where it
  would read as a clean result.
- Leak checks walk their targets instead of calling `JSON.stringify`, which asks each object what it
  wants to show. A `toJSON` that omits a field, a non-enumerable property, a value behind a getter,
  and a copy written into a `Buffer` are all reached; a value still wrapped in a `SensitiveString`
  is not reported.
- A wrapper whose rendering contains the whole raw value is reported as a leak rather than trusted,
  so a policy registered with `skipRedactValidation` cannot make a leak assertion pass.
- No failure message from the testing package contains the value it guards. A leak report replaces
  the value with `[LEAKED VALUE]`, and a failed `toRevealAs` reports the redacted rendering and the
  length, because an assertion message ends up in a CI log.
- `expectRedacted` checks the rendering the class policy actually produces, read from the instance,
  rather than hardcoding `[REDACTED:class]`, so it holds under a custom policy and fails when a
  policy stops redacting.
- `toRevealAs` reveals through the instance, so an expired value or a policy denial fails the
  assertion rather than passing on a value the code under test could not have read.
- Values the testing package generated are remembered by object identity so a leak check needs no
  reveal, which keeps it out of the caller's audit context and lets it run on an expired secret. The
  registry adds no property to the instance and is unreachable from outside the package.
- String transformations preserve sensitivity state and invoke reveal authorization and auditing.
- Partial queries are denied for credentials by default to prevent character-by-character oracle
  attacks.
- Replacement callbacks are rejected because they would receive raw matched content.
- Regex instances are snapshotted before raw access so overridden `exec` and symbol hooks cannot
  receive sensitive values; native match metadata containing the complete input is not returned.
- Regex queries follow `allowPartialQueries`, and credentials deny them by default to prevent
  caller-controlled pattern oracles.
- Template literals reveal each interpolated value through the authorization and audit gate, inherit
  the most restrictive class, and retain the state of every value they read.
- The template `klass` option may only tighten the inherited class, and unsupported interpolations
  are rejected with a `TypeError` that names the index and type but never the value, before any
  value is revealed.
- Masking is a partial reveal: it runs the same authorization and audit hooks as `reveal()`, and it
  follows `allowMask`, which credentials deny by default.
- The `minMasked` floor may be raised but not lowered, and a rendering that cannot hide that many
  characters falls back to the class's full redaction.
- A format strategy applied to a value that is not of that format redacts instead of degrading to a
  positional view, which would disclose a fixed prefix of whatever the value actually is. Counting
  digits is not enough to recognize a card: a hex token holds twelve or more of them among its
  letters.
- The `card` strategy is the only definition of card masking in this repository. It shows the
  six-digit BIN and the last four digits, which is the PCI-DSS maximum.
- The `email` strategy masks the domain as well as the local part, since a full domain leaks the
  employer or provider, and it hides a one-character local part completely.
- `customStrategy` receives the raw value, so it is rejected unless the caller names
  `strategy: 'custom'`, and its output is never measured against the floor.
- Mask options are validated before the value is read, so a rejected call leaves no audit record
  for a mask that was never rendered.
- Expiry is checked in the single gate every path to the raw value goes through, so `equals()`,
  `mask()`, `serialize()`, and every string, regex, and template operation refuse an expired value
  alongside `reveal()`. The check runs before authorization and before the audit hook, so a refusal
  is never logged as a reveal, and it cannot be lifted by overriding or shadowing `isExpired()`.
- Derived values carry the deadlines of every value they were built from and expire with the first
  of them, so a substring of an expired value is expired and a concatenation is usable only while
  both operands are.
- Only the value that owns a deadline may renew it. A derivative shares its sources' state by
  reference, so renewing through one would silently extend the value it came from.
- `ttl: 0` means "already expired" rather than "no TTL", and a value is not usable at its own
  deadline. A negative `ttl` is rejected rather than read as a deadline in the past.
- A policy's `allowRenewal: false` is a prohibition that the construction option cannot lift, and
  `maxTtl` is measured from construction, so no renewal can push an absolute lifetime forward.
- A renewal is audited before it takes effect, so an audit sink that throws stops it, and a renewal
  that a cap swallows entirely throws rather than reporting a success that changed nothing.
- Renewal permission and renewal counts do not cross the wire, so a payload cannot grant the right
  to extend a credential's lifetime; the receiving policy applies its own caps to a received
  deadline.
- An absolute deadline is read once, through the intrinsic `Date.prototype.getTime`, so neither
  mutating the `Date` afterwards nor overriding its `getTime` moves a deadline the library accepted.
- A finite but absurd `ttl` is rejected rather than accepted as a deadline past the largest date a
  `Date` can represent, which would never be reached and would throw on `serialize()`.
- `zSensitiveDeserialize()` reconstructs through `SensitiveString.deserialize()`, so the Zod
  receiving path carries a deadline and rejects an unregistered sensitivity class exactly as the
  core wire format does. It previously rebuilt the value and would have dropped the deadline,
  turning an expiring token into one that never expires.

## [0.1.0] - 2024-XX-XX

### Added

#### @platform-sec/sensitive-string-core
- `SensitiveString` class with ES2022 `#private` fields for true encapsulation
- Automatic redaction in `toString()`, `toJSON()`, and `util.inspect()`
- Sensitivity classification system: `sensitive` and `credential` (with optional labels)
- Policy registry with customizable redaction and security behaviors
- Constant-time comparison for the `credential` class
- `RevealContext` for audit-ready reveal operations
- `withRevealContext()` for AsyncLocalStorage-based context propagation
- `redactInStructure()` and `safeLog()` for safe logging of nested structures
- `SerializedSensitiveString` for service-to-service transmission
- Utility methods: `concat()`, `substring()`, `map()`, `reclassify()`, `isEmpty()`

#### @platform-sec/sensitive-string-zod
- `zSensitiveString()` for parsing strings into `SensitiveString` instances
- `zSensitive()` and `zCredential()` convenience helpers
- `zSensitiveWithValidation()` for custom string validation
- `zSensitiveOptional()` for nullable sensitive fields
- `zSensitiveDeserialize()` for parsing serialized format

### Security
- All serialization methods redact by default
- Timing-safe comparison for credentials
- Private fields inaccessible via reflection or type coercion
- Comprehensive test suite with canary leak detection
