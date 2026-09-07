import { Prisma } from '@prisma/client/extension';
import { normalizeConfig } from './config.js';
import type { SensitiveExtensionConfig } from './config.js';
import { revealRawArgs } from './args.js';
import { assertNoUnwrapped } from './guard.js';
import { assertConfigMatchesSchema } from './schema.js';
import { buildResultComponent } from './result.js';
import type { SensitiveResultComponent } from './types.js';

/**
 * Build the Prisma client extension.
 *
 * Two components, which is the whole design:
 *
 * The `result` component defines one computed field per classified column.
 * Prisma applies a result extension per model wherever that model appears in a
 * result, so relations loaded through `include` or `select` are covered by the
 * same definition, and the generated result types pick up each `compute`'s
 * declared return type. Nested wrapping and type inference are therefore
 * Prisma's, not this package's, and `select`, `include` and `omit` keep
 * narrowing normally.
 *
 * The `query` component installs one top-level `$allOperations` hook, which
 * Prisma runs for model operations and raw entry points alike. It does two
 * things, and the split between them is forced by the runtime rather than
 * chosen. Measured on Prisma 6.19.3 and 7.10.0, `applyQueryExtensions` calls
 * `deepCloneArgs` before it hands arguments to any extension, and that copy
 * keeps only the types Prisma knows. A `SensitiveString` is not one of them, so
 * a model argument arrives already flattened to `{ klass, label }` with the
 * value gone. A query extension therefore *cannot* unwrap a write, which is why
 * `sensitiveInput()` does the unwrapping at the call site.
 *
 * What the hook can do is:
 *
 * - unwrap the bound parameters of a tagged-template raw query, because
 *   `deepCloneArgs` rebuilds a `Sql` with its `values` array by reference and
 *   the instances in it are still live;
 * - refuse any operation still carrying the flattened remains of an instance,
 *   which is what turns a forgotten `sensitiveInput()` into a named error.
 *
 * That refusal is the point. Without it the mistake does not surface: on a
 * client with no query extension Prisma serialises the instance through
 * `toJSON()` and the column ends up holding `[REDACTED:credential]`. The secret
 * is destroyed, the write reports success, and a later lookup by the same
 * unwrapped value matches the corrupted row.
 *
 * Validation happens in two steps, and the second is the one that matters
 * most. The configuration's own shape is checked when this is called, so an
 * unregistered sensitivity class or a malformed entry throws before a client
 * exists. The model and column names are checked against the client when the
 * extension is applied, because neither TypeScript nor Prisma catches a typo
 * there: `models` is keyed by string, and Prisma silently ignores a result
 * component under a model it does not know and silently adds a computed field
 * under a name it does not know. Either way the column reads back as a plain
 * string, which is the failure this package exists to prevent.
 *
 * @param config - Models and fields to classify, plus the optional
 * `writeContext` and `detectUnwrapped`.
 * @returns An extension to pass to `client.$extends()`.
 * @throws PrismaConfigError If the configuration is malformed.
 *
 * @example
 * ```ts
 * const prisma = new PrismaClient({ adapter }).$extends(
 *   sensitiveExtension({
 *     models: {
 *       User: { email: 'sensitive', passwordHash: 'credential' },
 *     },
 *   })
 * );
 * const user = await prisma.user.findUniqueOrThrow({ where: { id: 1 } });
 * user.email; // SensitiveString<'sensitive'>
 * ```
 */
export function sensitiveExtension<const C extends SensitiveExtensionConfig>(config: C) {
  const normalized = normalizeConfig(config);

  // The callback form, so the models and columns can be checked against the
  // client this is applied to. Prisma's result-type inference is unaffected:
  // `$extends` reads the extension arguments off the returned client either
  // way, which `types.test-d.ts` asserts against a real generated client.
  return Prisma.defineExtension((client) => {
    assertConfigMatchesSchema(client, normalized);

    return client.$extends({
      name: 'sensitive-prisma',

      // Reads.
      //
      // The one cast in the package, and it is the seam between the two halves
      // of the read design. `buildResultComponent` works from the validated
      // runtime configuration, where the literal field names and classes are
      // gone, so its `compute` can only be declared as returning `unknown`.
      // The published type is a mapped type over the configuration literal,
      // which is what Prisma's inference reads to give `user.email` the type
      // `SensitiveString<'sensitive'>`. Neither can be derived from the other.
      //
      // What checks it is `types.test-d.ts`, which asserts the field types the
      // extension actually publishes against a real generated client, with a
      // negative control so the assertions cannot pass vacuously.
      result: buildResultComponent(normalized) as unknown as SensitiveResultComponent<C>,

      // Raw parameters, and the guard on everything else. One top-level hook:
      // Prisma runs `$allOperations` for `$queryRaw`, `$executeRaw`, their
      // `Unsafe` variants and `$runCommandRaw` as well as for every model
      // operation, measured on both major versions.
      query: {
        $allOperations({ model, operation, args, query }) {
          const next =
            model === undefined
              ? revealRawArgs(args, { model, operation, ...normalized.writeContext })
              : args;

          if (normalized.detectUnwrapped) {
            assertNoUnwrapped(next, { model, operation });
          }

          return query(next as typeof args);
        },
      },
    });
  });
}
