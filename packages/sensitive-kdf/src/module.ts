import { MissingKdfModuleError } from './errors.js';

/**
 * Loading an optional native module.
 *
 * The specifier is held in a variable on purpose. A literal would put `argon2`
 * and `bcrypt` into this package's type graph and into whatever a consumer's
 * bundler decides to resolve, and both are optional peer dependencies that
 * most installations will not have: an application hashing with scrypt should
 * not have to install two native modules to compile.
 *
 * The cost is that nothing here is type-checked against the real module, which
 * is why each adapter declares the narrow shape it uses and why the round-trip
 * tests are the thing that actually holds these bindings to the modules.
 */
async function importModule(specifier: string): Promise<Record<string, unknown>> {
  const loaded: unknown = await import(specifier);

  if (loaded === null || typeof loaded !== 'object') {
    throw new TypeError(`The '${specifier}' package did not load as a module`);
  }

  return loaded as Record<string, unknown>;
}

/**
 * An optional module's exports, flattened.
 *
 * A CommonJS module reached through `import()` arrives as a namespace whose
 * `default` is `module.exports`, with the named exports Node's lexer could
 * detect alongside it. Both of these packages are CommonJS, and which of the
 * two forms carries a given function depends on Node's detection rather than
 * on anything this package controls, so the named export is preferred and
 * `default` is the fallback.
 *
 * @throws MissingKdfModuleError If the module cannot be loaded at all.
 */
export async function loadKdfModule(
  specifier: string,
  algorithm: string
): Promise<Record<string, unknown>> {
  let namespace: Record<string, unknown>;

  try {
    namespace = await importModule(specifier);
  } catch (error) {
    throw new MissingKdfModuleError(specifier, algorithm, error);
  }

  const fallback = namespace['default'];

  if (fallback === null || typeof fallback !== 'object') {
    return namespace;
  }

  return { ...(fallback as Record<string, unknown>), ...namespace };
}
