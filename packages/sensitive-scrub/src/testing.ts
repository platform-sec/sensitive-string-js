import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

/**
 * The canary harness vendor suites import.
 *
 * Framework-free, like `@platform-sec/sensitive-string-testing`: these are
 * plain functions that throw an ordinary `Error`, so a suite can run them
 * under Vitest, Jest, or `node --test` without any of them being a dependency
 * of this package.
 *
 * 3.7's security constraints say an integration that transmits throws if the
 * outgoing bytes contain `[REDACTED:`. Applied to an error tracker that is
 * backwards. A tracker is a sink, not a wire: the marker is the desired output
 * and its absence is the failure. So the assertion that belongs here is the
 * mirror, a canary in every capturable position asserted absent from the
 * outgoing envelope.
 */

/** The core names one package's shipped source imports, and where from. */
export interface CoreImport {
  /** The file, relative to the directory that was scanned. */
  readonly file: string;
  /** One imported binding, `type` prefixes stripped. */
  readonly name: string;
}

/**
 * Every name a package's shipped source imports from core.
 *
 * A scrubbing package that calls `reveal()` has inverted its own purpose. The
 * import list is where that becomes visible without trying to tell
 * `SensitiveString.prototype.map` from `Array.prototype.map` by text search,
 * which is why the invariant is written against the imports rather than
 * against a grep for a method name.
 *
 * Only shipped source is scanned. A test that imports `redactInStructure` to
 * pin how it differs from `redactCopy` is doing its job, and nothing it
 * imports reaches a published artifact.
 *
 * @param dir - A package's `src` directory
 */
export function findCoreImports(dir: string): CoreImport[] {
  const found: CoreImport[] = [];

  for (const file of sourceFiles(dir)) {
    const text = readFileSync(join(dir, file), 'utf8');

    for (const match of text.matchAll(CORE_IMPORT)) {
      const clause = match[1];

      if (clause === undefined) {
        continue;
      }

      for (const binding of clause.split(',')) {
        const name = binding
          .replace(/^\s*type\s+/, '')
          .split(/\s+as\s+/)[0]
          ?.trim();

        if (name !== undefined && name !== '') {
          found.push({ file, name });
        }
      }
    }
  }

  return found;
}

/** A named import from core, in either the value or the type position. */
const CORE_IMPORT =
  /import\s+(?:type\s+)?\{([^}]*)\}\s+from\s+'@platform-sec\/sensitive-string-core'/g;

function sourceFiles(dir: string, prefix = ''): string[] {
  const files: string[] = [];

  for (const entry of readdirSync(join(dir, prefix), { withFileTypes: true })) {
    const relative = prefix === '' ? entry.name : `${prefix}/${entry.name}`;

    if (entry.isDirectory()) {
      if (entry.name !== '__tests__' && entry.name !== 'node_modules') {
        files.push(...sourceFiles(dir, relative));
      }

      continue;
    }

    if (
      entry.name.endsWith('.ts') &&
      !entry.name.endsWith('.test.ts') &&
      !entry.name.endsWith('.test-d.ts')
    ) {
      files.push(relative);
    }
  }

  return files;
}

/** Where a canary was found, as a dotted path into the searched value. */
export interface CanarySighting {
  readonly path: string;
  /** A short window around the sighting, with the canary itself elided. */
  readonly context: string;
}

/**
 * Build a conspicuous, unique canary.
 *
 * Unique per call so a stale value cached from an earlier test cannot pass for
 * a fresh one, and conspicuous so a sighting in CI output is unmistakable.
 */
export function createCanary(name = 'CANARY'): string {
  const suffix = Math.random().toString(36).slice(2, 10);

  return `LEAKED_${name.toUpperCase()}_${suffix}`;
}

/**
 * Every position in a value where a canary appears.
 *
 * Searches strings, arrays, objects, `Map` and `Set` contents, and the decoded
 * text of a `Buffer`, `Uint8Array`, or `ArrayBuffer`, because a vendor
 * envelope is bytes by the time a transport sees it. A getter that throws is
 * skipped rather than failing the sweep, since the point of the sweep is to
 * search everywhere it can reach.
 */
export function findCanary(value: unknown, canary: string): CanarySighting[] {
  const sightings: CanarySighting[] = [];

  search(value, canary, '', sightings, new WeakSet());

  return sightings;
}

/**
 * Assert a canary appears nowhere in a value.
 *
 * @throws Error naming every path it was found at.
 */
export function expectNoCanary(value: unknown, canary: string, subject = 'payload'): void {
  const sightings = findCanary(value, canary);

  if (sightings.length === 0) {
    return;
  }

  const detail = sightings.map((s) => `  ${s.path === '' ? '<root>' : s.path}: ${s.context}`);

  throw new Error(
    `canary leaked into ${subject} at ${sightings.length} position(s):\n${detail.join('\n')}`
  );
}

/**
 * Assert a canary appears somewhere in a value.
 *
 * The counterpart the sweep needs to stay honest: a test that places a canary
 * in a position the SDK silently drops proves nothing, and would keep passing
 * if the scrubber were deleted. A sweep asserts presence before scrubbing and
 * absence after.
 *
 * @throws Error when the canary is absent.
 */
export function expectCanaryPresent(value: unknown, canary: string, subject = 'payload'): void {
  if (findCanary(value, canary).length > 0) {
    return;
  }

  throw new Error(
    `canary is absent from ${subject}, so this position proves nothing about the scrubber`
  );
}

function search(
  value: unknown,
  canary: string,
  path: string,
  sightings: CanarySighting[],
  seen: WeakSet<object>
): void {
  if (typeof value === 'string') {
    if (value.includes(canary)) {
      sightings.push({ path, context: elide(value, canary) });
    }

    return;
  }

  if (value === null || typeof value !== 'object') {
    return;
  }

  if (seen.has(value)) {
    return;
  }
  seen.add(value);

  const bytes = asBytes(value);

  if (bytes !== null) {
    const text = Buffer.from(bytes).toString('utf8');

    if (text.includes(canary)) {
      sightings.push({ path: `${path}<bytes>`, context: elide(text, canary) });
    }

    return;
  }

  if (value instanceof Map) {
    for (const [key, item] of value) {
      search(key, canary, `${path}<key>`, sightings, seen);
      search(item, canary, `${path}.${String(key)}`, sightings, seen);
    }

    return;
  }

  if (value instanceof Set) {
    let index = 0;

    for (const item of value) {
      search(item, canary, `${path}.${index}`, sightings, seen);
      index += 1;
    }

    return;
  }

  if (value instanceof Error) {
    search(value.message, canary, `${path}.message`, sightings, seen);
    search(value.stack ?? '', canary, `${path}.stack`, sightings, seen);
  }

  for (const key of ownKeys(value)) {
    const child = read(value, key);
    const childPath = path === '' ? key : `${path}.${key}`;

    search(child, canary, childPath, sightings, seen);
  }
}

function asBytes(value: object): Uint8Array | null {
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }

  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }

  return null;
}

function ownKeys(value: object): string[] {
  try {
    return Object.getOwnPropertyNames(value);
  } catch {
    return [];
  }
}

function read(value: object, key: string): unknown {
  try {
    return (value as Record<string, unknown>)[key];
  } catch {
    return undefined;
  }
}

/**
 * A window around a sighting with the canary replaced.
 *
 * Reporting where the leak is without reprinting it, so a CI log of a failing
 * canary test is not itself a copy of the value.
 */
function elide(text: string, canary: string): string {
  const at = text.indexOf(canary);
  const before = text.slice(Math.max(0, at - 24), at);
  const after = text.slice(at + canary.length, at + canary.length + 24);

  return `...${before}<CANARY>${after}...`;
}
