# Repository Guidelines

## Project Structure & Module Organization

This is a pnpm workspace for Node.js 22.12+ and TypeScript. Packages live under `packages/`:

- `packages/sensitive-core/src/` contains the redaction, policy, context, and wrapping APIs.
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
- `packages/sensitive-vault/src/` contains the Vault and OpenBao source: the KV v1 and v2 wire
  shapes, the `lease_duration` converter, dynamic secret leases, response wrapping, and the flavor
  flag with its divergence table. It takes core and `sensitive-secrets` as peers and has no vendor
  SDK, because the API surface it needs is a handful of endpoints over `fetch`. Its unit suite runs
  against a fake transport; `src/__tests__/live.test.ts` skips itself unless `VAULT_ADDR` and
  `VAULT_TOKEN` are set, and the `vault-compat` CI job runs it against Vault and OpenBao containers.
- `packages/sensitive-eslint-plugin/src/` contains the ESLint rules, their presets, and the
  parser-agnostic AST helpers they share. It has no runtime dependencies, not even on the core
  package: the rules read syntax, never types. Each rule's user-facing documentation is in
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
- `pnpm test` runs the Vitest suite once; `pnpm test:watch` supports local iteration.
- `pnpm test:coverage` writes V8 text, JSON, and HTML coverage reports.
- `pnpm lint` runs type-aware ESLint; `pnpm lint:fix` applies safe fixes.
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
