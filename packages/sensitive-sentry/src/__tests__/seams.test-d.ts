import type { NodeOptions } from '@sentry/node';
import { expectTypeOf } from 'vitest';

import { COVERED_HOOKS } from '../install.js';

/**
 * The seam inventory, checked against the SDK's own option type.
 *
 * `beforeSend` is one of six public `before*` options in `@sentry/core`
 * 10.73.0. A package that covers the seams which existed when it was written,
 * and is then installed against a newer SDK, covers less than it claims and
 * says nothing about it. That is the failure mode this file exists for.
 *
 * A seventh hook in a future SDK minor fails compilation of the repository
 * program with the new hook's name in the failure, and a hook the SDK removes
 * fails it from the other direction. This is worth more than a runtime
 * assertion because it fires on `pnpm update` rather than on the first event
 * that uses the new path.
 *
 * This file is named `.test-d.ts` rather than `.test.ts` deliberately. It is
 * checked by `pnpm typecheck`, which compiles every package under one program,
 * and it is not collected by `vitest run`, which has nothing to execute here.
 */
type SdkBeforeHooks = Extract<keyof NodeOptions, `before${string}`>;
type Covered = (typeof COVERED_HOOKS)[number];

// Both directions, so neither a new SDK hook nor a stale name here passes.
expectTypeOf<SdkBeforeHooks>().toEqualTypeOf<Covered>();

/** A hook the SDK declares and this package does not compose. Must be `never`. */
type Uncovered = Exclude<SdkBeforeHooks, Covered>;
expectTypeOf<Uncovered>().toEqualTypeOf<never>();

/** A hook this package names and the SDK does not declare. Must be `never`. */
type Phantom = Exclude<Covered, SdkBeforeHooks>;
expectTypeOf<Phantom>().toEqualTypeOf<never>();

/** Every covered name really is an option key, so the composition type-checks. */
expectTypeOf<Covered>().toExtend<keyof NodeOptions>();
