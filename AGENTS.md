# Repository Guidelines

## Project Structure & Module Organization

This is a pnpm workspace for Node.js 22.12+ and TypeScript. Packages live under `packages/`:

- `packages/sensitive-core/src/` contains the redaction, policy, context, and wrapping APIs.
  `probe.ts` holds the guarded reads every walk uses against objects it did not create: an arbitrary
  object controls the tag read, the prototype read, `has`, `toJSON`, `ownKeys`,
  `getOwnPropertyDescriptor`, every enumerable getter, `toString`, and behind a Proxy the iteration
  of a Map, Set or array and every method of a Date, and a throw from any of them used to take the
  redaction down with it. `src/__tests__/hostile-objects.test.ts` drives every one
  of those hooks against every walk; extend that table rather than assuming it is complete, because
  each of the three rounds of this defect was found by widening it and none by reading the code.
- `packages/sensitive-zod/src/` contains the Zod integration and depends on the core package.
- `packages/sensitive-testing/src/` contains the test utilities: canary secrets, leak and redaction
  assertions, matchers, and audit mocks. It depends on the core package and on no test framework.
- `packages/sensitive-decorators/src/` contains the framework-agnostic Stage 3 decorators:
  `@Sensitive` for auto-accessor fields and `@WithRevealContext` for methods. It depends only on
  the core package and compiles under the root `tsconfig.json`, which leaves `experimentalDecorators`
  off. It shares two decorator names with `sensitive-nestjs` and no code, because the two decorator
  models cannot be compiled together.
- `packages/sensitive-nestjs/src/` contains the NestJS integration: the `@Sensitive` DTO decorator,
  the transform pipe, the context and response interceptors, and the parameter decorators. It is the
  one package compiled with `experimentalDecorators` and `emitDecoratorMetadata`, which NestJS
  requires, so it is excluded from the root `tsconfig.json` program and checked through its own
  `tsconfig.json` instead. Its tests compile through swc rather than esbuild, because esbuild emits
  no decorator metadata and NestJS needs `design:paramtypes` to tell a pipe which DTO class a
  parameter has; `vitest.config.ts` scopes that transform to this package.
- `packages/sensitive-express/src/` contains the Express integration: `sensitiveBody`,
  `sensitiveHeaders`, `sensitiveContext`, `sensitiveResponseFilter`, and `stripParseErrorBody`. It
  depends on the core package and on Express as peers, and compiles under the root
  `tsconfig.json`. Its suite runs against Express 5, plus a smoke test against Express 4 through the
  `express4` devDependency alias. That alias's ambient typings live in `packages/sensitive-express/types/`
  rather than under `src`, because `.gitignore` and `pnpm clean` both treat a declaration file under a
  package's `src` as build output.
- `packages/sensitive-scrub/src/` contains the shared layer under the error tracking and APM
  integrations: the staged payload walk over `redactCopy`, `DEFAULT_DENY_KEYS` and its matcher, the
  never-throw wrapper, and the canary harness vendor suites import from `./testing`. It has no
  third-party runtime dependencies and takes the core package as a peer, because structural
  redaction is `instanceof` checks and two copies of core make them all miss.
- `packages/sensitive-sentry/src/` contains the Sentry integration: `withSensitiveScrubbing`, which
  composes all six of the SDK's `before*` hooks and appends an integration whose `setup()` registers
  the scope event processor, plus `recommendedDataCollection` and the Sentry-shaped payload paths. It
  takes core, `sensitive-scrub`, and `@sentry/node` as peers, and its suite drives the real SDK to a
  capturing transport rather than mocking it.
- `packages/sensitive-secrets/src/` contains the shared layer under the secrets manager
  integrations: the `SecretSource` interface, the classification policy over core's
  `ClassificationSpec`, the decode guard that keeps a payload out of a `SyntaxError`, the label rule,
  the instance cache with single-flight and TTL alignment, the file watcher, and the sweep harness
  provider suites import from `./testing`. The write guard is a separate entry point, `./write`, so
  an application that only reads never loads it. It has no third-party runtime dependencies and
  takes the core package as a peer.
- `packages/sensitive-env/src/` contains the shared loader under the config and environment
  integrations: the `EnvSpec` over core's `ClassificationSpec`, the opt-in `commonSecretNameRules`
  pack, `wrapFlat` by exact key and `wrapTree` over core's path walker, the `util.parseEnv` wrapper
  with its dropped-line report, deletion from `process.env` with the `/proc/self/environ` name check
  that says what deletion cannot reach, `toChildEnv` with the marker guard, and the canary harness
  the `envalid` suite imports from `./testing`. It has no third-party runtime dependencies and takes
  the core package as a peer. It dev-depends on convict, node-config, dotenv and dotenv-expand with
  no peer or runtime relationship to any of them, so that the third-party pins in
  `src/__tests__/third-party-pins.test.ts` actually run: those three libraries are recipes in the
  README rather than packages, because dotenv holds nothing to wrap and the other two clone their
  trees on read.
- `packages/sensitive-envalid/src/` contains the envalid integration: `makeSensitiveValidator` over
  envalid's own `makeValidator` so the class survives into the inferred type, the four
  construction-time refusals (`default`, `devDefault`, `testDefault` and `choices`, each of which
  quietly does the wrong thing), and `cleanEnvSafe`, whose reporter rebuilds envalid's aggregate
  report without the raw input every built-in validator embeds in it and throws instead of calling
  `process.exit`. It takes core, `sensitive-env` and `envalid` as peers.
- `packages/sensitive-vault/src/` contains the Vault and OpenBao source: the KV v1 and v2 wire
  shapes, the `lease_duration` converter, dynamic secret leases, response wrapping, and the flavor
  flag with its divergence table. It takes core and `sensitive-secrets` as peers and has no vendor
  SDK, because the API surface it needs is a handful of endpoints over `fetch`. Its unit suite runs
  against a fake transport; `src/__tests__/live.test.ts` skips itself unless `VAULT_ADDR` and
  `VAULT_TOKEN` are set, and the `vault-compat` CI job runs it against Vault and OpenBao containers.
- `packages/sensitive-aws-secrets/src/`, `packages/sensitive-azure-keyvault/src/`,
  `packages/sensitive-gcp-secrets/src/` and `packages/sensitive-oci-vault/src/` contain the four
  cloud secrets manager sources. Each is an `index.ts`, a `source.ts` and a wire-shape module, which
  is the point of the shared layer. All four take core and `sensitive-secrets` as peers. Only
  `aws-secrets` imports its vendor SDK at run time, because AWS v3 dispatches through command
  objects that have to be constructed; the other three declare theirs as a types-only peer, so their
  built output contains no vendor import and their fixtures are still typed as the SDK's own
  response types.
- `packages/sensitive-k8s/src/` contains the Kubernetes source: the API read path, the built-in
  classification specs per Secret type, the unconditional annotation strip, the bound service
  account token decode, and `K8sMountedSource` over the shared file watcher. Its unit suite runs
  against typed fixtures; `src/__tests__/live.test.ts` skips itself unless `K8S_KUBECONFIG` is set,
  and the `secrets-live` CI job runs it against a k3s container.
- `packages/sensitive-sops/src/` contains the SOPS source: the subprocess boundary, the age key that
  reaches the child's environment and never the parent's, classification derived from the `ENC[`
  markers in the ciphertext, and `decryptAge` behind its own `./age` entry point. Its unit suite
  runs against `src/__tests__/fake-sops.mjs`, a stand-in binary; `src/__tests__/live.test.ts` skips
  itself unless the real `sops` is on `PATH` or named by `SOPS_BINARY`.
- `packages/sensitive-doppler/src/` and `packages/sensitive-infisical/src/` contain the two
  REST-only secret sources. Neither has a vendor SDK or any third-party runtime dependency: one
  endpoint over `fetch` each, with the transport interface exported. Neither has a live tier, and
  both READMEs say so.
- `packages/sensitive-http/src/` contains the shared layer under the HTTP client integrations: the one
  reveal walker and the `ScrubPlan` it records, the marker guard in its literal, percent-encoded and
  base64 forms, the auth header descriptors, the scrub for both settlement paths, the redirect host
  policy and the URL scheme check, the response decoder, and the per-attempt context builder. The
  recording server every client suite asserts bytes against is a separate entry point, `./testing`.
  It has no third-party runtime dependencies and takes the core package as a peer. Two modules,
  `reveal.ts` and `auth.ts`, are the only places in the whole row that call `reveal()`;
  `src/__tests__/no-bypass.test.ts` is a source scan that keeps that true across all six packages,
  so a reviewer checks the property by reading two files rather than sixty.
- `packages/sensitive-axios/src/`, `packages/sensitive-got/src/`, `packages/sensitive-ky/src/`,
  `packages/sensitive-fetch/src/` and `packages/sensitive-undici/src/` contain the five client
  wrappers. Each is an `index.ts`, a `client.ts` and a `scrub.ts` holding that client's property
  list, which is the point of the shared layer. All five take core and `sensitive-http` as peers,
  plus their client where there is one; `sensitive-fetch` has no third-party peer at all because
  Node 22 provides `fetch`. The wrapper owns the call rather than installing a hook, because the
  clients disagree about which half of a request a hook can still reach and because the measured
  damage is after the send, where no hook runs. Two of the scrubs drop a request object rather than
  rewriting it: a Node `ClientRequest` keeps the outgoing header block in `_header` and a
  `kOutHeaders` symbol that no supported API reaches, and that is deliberate, conditional on the
  request having carried a sensitive value, and documented in both READMEs. The got suite covers both
  peer majors through the `got14` devDependency alias, whose ambient typings live in
  `packages/sensitive-got/types/` for the same reason the Express 4 ones do. Each client suite
  asserts the **bare** client's behaviour before the wrapper's, so the suite records the leak it is
  compensating for and fails if a client ever fixes it; the `http-client-compat` CI job runs the same
  suites against the latest client releases rather than the lockfile pins, which is what turns them
  into regression tests against the clients. `packages/sensitive-http/src/testing.test.ts` tests the
  recording server itself, because a harness that silently drops a header would make every canary
  assertion in six packages pass for the wrong reason.
- `packages/sensitive-eslint-plugin/src/` contains the ESLint rules, their presets, and the
  parser-agnostic AST helpers they share. It has no dependencies, not even on the core package, and
  not on `typescript`: five rules read syntax only, and the two that need types reach the checker
  structurally through `parserServices`, which whoever configured type-aware linting already built.
  Those two carry `meta.docs.requiresTypeChecking`, which is what `configs.ts` splits the presets on
  and what keeps them out of a preset that runs over plain JavaScript. Their suites lint inside
  `src/__tests__/fixtures/`, a throwaway project whose `file.ts` exists only so the parser has a
  program member to replace. Each rule's user-facing documentation is in
  `packages/sensitive-eslint-plugin/docs/rules/`.
- Tests are colocated as `*.test.ts`; larger adversarial suites live in `src/__tests__/`.
- `examples/` contains checked TypeScript usage examples. Shared compiler and test settings are in `tsconfig.base.json` and `vitest.config.ts`; CI and supply-chain automation live in `.github/`.

Generated `dist/`, coverage, CodeQL, and scratch artifacts must not be committed.

## Build, Test, and Development Commands

Use pnpm 9; the preinstall hook rejects other package managers.

- `pnpm install --frozen-lockfile` installs the exact dependency graph.
- `pnpm build` compiles every workspace package to its `dist/` directory.
- `pnpm typecheck` type-checks packages and examples together, apart from `sensitive-nestjs`; that
  one is checked with `pnpm --filter @platform-sec/sensitive-string-nestjs exec tsc --noEmit`. This
  is what runs the `.test-d.ts` seam checks, which `vitest` does not collect and a package build
  excludes, so an integration claiming to cover a vendor's hooks fails here when the vendor adds one.
- `pnpm test` runs the Vitest suite once; `pnpm test:watch` supports local iteration. A suite that
  imports another workspace package by name resolves it through that package's `exports` map, so it
  runs against `dist` rather than source: build before running one of those, or a change to the
  dependency is invisible to the tests that exercise it. Colocated tests that import by relative
  path are unaffected. This also decides whether a check that a test guards what it claims means
  anything: breaking the dependency on purpose and rerunning proves nothing without the rebuild,
  because the run still exercises the old `dist`, passes, and leaves a vacuous test looking exactly
  like a load bearing one.
- The `http-client-compat` job installs `axios@latest`, `got@latest`, `ky@latest` and
  `undici@latest` over the lockfile and reruns the six HTTP client suites. It is informational, like
  the two live tiers, and it writes the resolved versions into the run summary so the measurement
  tables in `packages/sensitive-http/README.md` can say which versions they last held for.
- A provider package's unit suite runs against fixtures and never a live service. Three of them have
  a second tier under `src/__tests__/live.test.ts`, each self-skipping on an environment variable:
  `sensitive-vault` (`VAULT_ADDR`), `sensitive-k8s` (`K8S_KUBECONFIG`), `sensitive-sops`
  (`SOPS_BINARY` or `sops` on `PATH`) and `sensitive-aws-secrets` (`AWS_SECRETS_ENDPOINT`, an
  emulator). A fixture written from a design document tests the document rather than the provider,
  which is how four defects in this row reached a passing unit suite; the live tiers are what catch
  that class, so run them before trusting a wire-shape change.
- `pnpm build` is also what type-checks a package's own emit. Vitest transforms TypeScript with
  esbuild, which strips types without checking them, so a type error can pass the suite and fail the
  build.
- `pnpm test:coverage` writes V8 text, JSON, and HTML coverage reports. It excludes
  `src/__benchmarks__`, which is source under `src` that would otherwise be counted as uncovered
  library code.
- `pnpm bench` runs the performance benchmarks through `vitest.bench.config.ts`. They live in
  `packages/*/src/__benchmarks__/*.bench.ts`, are excluded from every package build so they ship
  nowhere, and take several minutes. Like the timing analysis they measure the wall clock, so they
  gate nothing; a benchmark is written with a control in its `describe` group, because the ratio
  between the two is what carries across machines while the absolute figures do not.
- `pnpm lint` runs type-aware ESLint; `pnpm lint:fix` applies safe fixes. Both set a 6 GB Node heap,
  because they need it: type-aware linting follows imports into the vendor type declarations, and the
  secrets manager providers pull in the AWS SDK, the Kubernetes client and the generated GCP
  protobuf definitions, the last of which is enormous. Without the larger heap the run is OOM-killed
  partway through on a 10 GB machine, and a killed lint looks like a passing one to any wrapper that
  reads the exit code of a pipeline rather than of ESLint itself. Expect several minutes. Reducing
  that cost, by scoping the typed rules so a package's lint program does not include every vendor
  graph, is worth doing and has not been done.
- `pnpm format` formats package TypeScript sources with Prettier.
- `pnpm check:packaging` loads every built package by its own name through both `require` and
  `import`, and checks that each path a manifest names exists and survives packing. Run it after
  `pnpm build`; the unit suite imports by relative path and never exercises a manifest.

Before opening a PR, run build, lint, tests, the root type-check, and the packaging check.

## Coding Style & Naming Conventions

Write strict ES2022 TypeScript using NodeNext modules. Prettier enforces two-space indentation, single quotes, semicolons, trailing commas, and a 100-column width. Use `camelCase` for values/functions, `PascalCase` for types/classes, and kebab-case filenames such as `sensitive-string.ts`. Prefix intentionally unused parameters with `_`. Add JSDoc to public APIs.

## Testing & Security Guidelines

Use Vitest `describe`/`it` blocks and name files `*.test.ts`. New behavior requires positive, edge-case, and adversarial coverage; maintain the documented target above 90%. Sensitive-value tests must use a conspicuous `CANARY` value and assert that logs, errors, inspection, and serialization do not contain it. Preserve ES `#private` fields and default redaction. Treat changes to reveal, serialization, policies, comparison, or context propagation as security-impacting.

## Commits & Pull Requests

History follows Conventional Commits, commonly scoped: `feat(core): ...`, `fix(zod): ...`, `test(core): ...`; append `!` for breaking changes. Keep commits focused. PRs should describe intent and security impact, link relevant issues, list verification commands, and add tests. Update README/JSDoc for public APIs and `CHANGELOG.md` for user-visible changes. Security-impacting changes require maintainer review; report vulnerabilities privately rather than in public issues.
