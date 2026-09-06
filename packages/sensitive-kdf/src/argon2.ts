import { MissingKdfModuleError, UnknownStoredHashError } from './errors.js';
import { loadKdfModule } from './module.js';
import type { Argon2Plan } from './options.js';

/**
 * Argon2, through the optional `argon2` package.
 *
 * The winner of the Password Hashing Competition and the first choice for a
 * new system: memory-hard, so an attacker's GPUs lose most of their advantage,
 * and `argon2id` is the variant that resists both side channels and
 * time-memory tradeoffs.
 */

/** The narrow shape this package uses, since the module is not in its type graph. */
interface Argon2Module {
  hash(
    value: string,
    options: {
      type: number;
      memoryCost: number;
      timeCost: number;
      parallelism: number;
      hashLength: number;
    }
  ): Promise<string>;
  verify(stored: string, value: string): Promise<boolean>;
  readonly argon2id: number;
  readonly argon2i: number;
  readonly argon2d: number;
}

async function argon2Module(): Promise<Argon2Module> {
  const loaded = await loadKdfModule('argon2', 'Argon2');

  if (typeof loaded['hash'] !== 'function' || typeof loaded['verify'] !== 'function') {
    throw new MissingKdfModuleError('argon2', 'Argon2');
  }

  return loaded as unknown as Argon2Module;
}

function variant(module: Argon2Module, algorithm: Argon2Plan['algorithm']): number {
  const type =
    algorithm === 'argon2id'
      ? module.argon2id
      : algorithm === 'argon2i'
        ? module.argon2i
        : module.argon2d;

  // The numeric ids are 0, 1 and 2 and could be written down here. Reading them
  // from the module instead is what keeps a future renumbering from quietly
  // hashing every password with a different variant than the one asked for.
  if (typeof type !== 'number') {
    throw new MissingKdfModuleError('argon2', 'Argon2');
  }

  return type;
}

/** Hash a password. The result is a PHC string carrying the parameters and salt. */
export async function hashArgon2(value: string, plan: Argon2Plan): Promise<string> {
  const module = await argon2Module();

  return module.hash(value, {
    type: variant(module, plan.algorithm),
    memoryCost: plan.memoryCost,
    timeCost: plan.timeCost,
    parallelism: plan.parallelism,
    hashLength: plan.hashLength,
  });
}

/**
 * Verify a password against a stored Argon2 hash.
 *
 * The parameters come from the stored string rather than from any configured
 * default, which is what lets a store hashed under weaker parameters keep
 * verifying while new hashes use stronger ones.
 *
 * Anything the module throws becomes an {@link UnknownStoredHashError} with no
 * cause attached: the messages it raises for a malformed hash quote the string
 * it was given, and that string is a credential.
 */
export async function verifyArgon2(stored: string, value: string): Promise<boolean> {
  const module = await argon2Module();

  try {
    return await module.verify(stored, value);
  } catch {
    throw new UnknownStoredHashError('the argon2 module could not read it');
  }
}
