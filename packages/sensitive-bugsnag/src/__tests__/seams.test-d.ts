import type { Config } from '@bugsnag/js';
import { expectTypeOf } from 'vitest';

import { COVERED_CALLBACKS, EXCLUDED_CALLBACKS, type BugsnagConfig } from '../install.js';

/**
 * The seam inventory, checked against the SDK's own config type.
 *
 * Bugsnag's seams are not a `before*` family the way Sentry's are, so this is an
 * explicit list checked in both directions rather than a single pattern match:
 * three callbacks that are payload seams and two that are not. A fourth `on*`
 * option in a future SDK release fails compilation of the repository program
 * with the new name in the failure, which is worth more than a runtime
 * assertion because it fires on `pnpm update` rather than on the first event
 * that uses the new path.
 *
 * `BugsnagConfig` is the union of `BrowserConfig` and `NodeConfig`, and
 * `keyof` a union is only the keys both members share, which would hide a
 * Node-only seam. The conditional distributes over the union so both members
 * contribute, which is how `onUncaughtException` shows up here at all.
 *
 * This file is named `.test-d.ts` rather than `.test.ts` deliberately. It is
 * checked by `pnpm typecheck` and is not collected by `vitest run`, which has
 * nothing to execute here.
 */
type OnKeys<T> = T extends unknown ? Extract<keyof T, `on${string}`> : never;

type SdkCallbacks = OnKeys<BugsnagConfig>;
type Covered = (typeof COVERED_CALLBACKS)[number];
type Excluded = (typeof EXCLUDED_CALLBACKS)[number];

// Both directions, so neither a new SDK callback nor a stale name here passes.
expectTypeOf<SdkCallbacks>().toEqualTypeOf<Covered | Excluded>();

/** A callback the SDK declares that this package neither composes nor excuses. */
type Unaccounted = Exclude<SdkCallbacks, Covered | Excluded>;
expectTypeOf<Unaccounted>().toEqualTypeOf<never>();

/** A callback this package names and the SDK does not declare. */
type Phantom = Exclude<Covered | Excluded, SdkCallbacks>;
expectTypeOf<Phantom>().toEqualTypeOf<never>();

/**
 * The three composed names really are options on the shared `Config`, so the
 * composition type-checks and so a browser build is covered by the same three.
 */
expectTypeOf<Covered>().toExtend<keyof Config>();

/** The list this package feeds into the vendor's own encoder is an option too. */
expectTypeOf<'redactedKeys'>().toExtend<keyof Config>();
