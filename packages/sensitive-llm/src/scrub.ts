import {
  failedReport,
  mergeScrubPolicy,
  pathDenied,
  reportScrub,
  resolveScrubPolicy,
  scrubPayload,
  type PayloadKind,
  type ResolvedScrubPolicy,
} from '@platform-sec/sensitive-string-scrub';

import { handlePattern } from './handle.js';
import { DEFAULT_CONTENT_PATHS, LLM_DENY_KEYS } from './shapes.js';
import type {
  PromptManifest,
  PromptScrubOptions,
  PromptScrubResult,
  PromptScrubber,
} from './types.js';

/**
 * Structural scrubbing of a request body bound for a model.
 *
 * This closes the smaller half of the leak, and saying so plainly is part of
 * the feature. A request body sorts into three positions and only one of them
 * has a good defence:
 *
 * 1. **Structured, wrapped.** A `SensitiveString` at a key, or a `serialize()`
 *    result at one. Already safe under `toJSON()`, and safe under `redactCopy`
 *    for the serialized form, which is the one shape `toJSON()` cannot save.
 *    Covered, and the coverage is real.
 * 2. **Structured, unwrapped.** A plain string at a key the application
 *    controls. Covered to the extent that the key has a credential-shaped
 *    name, which for a request body is mostly true of the envelope and mostly
 *    false of the content.
 * 3. **Prose.** A string in `messages[].content`, in a system prompt, in a
 *    retrieved document appended to context, in a tool result echoed back. Not
 *    covered, and cannot be by a denylist. The key is `content`. The key is
 *    always `content`. It carries no information about what is inside it, and
 *    the thing inside it is the reason the request exists, so denying the key
 *    denies the request.
 *
 * Position 3 is where a leak actually happens in a retrieval-augmented
 * application. What this package offers there is a seam, `transformContent`,
 * for a classifier the caller already runs, and the honest sentence in the
 * README rather than the implication of coverage.
 *
 * ## Why there is no content classifier here
 *
 * A sweep that misses is worse than no sweep: a caller who has installed a PII
 * scrubber stops reading their prompts, and the failure mode of a partial
 * classifier is not "some leaks get through" but "the reviewer stops looking".
 * The library also has no scanner and the thing that resembles one is not:
 * `core.patterns` has one entry, `email`, anchored at both ends, which answers
 * "is this whole string an address" rather than "is there one in this
 * paragraph". And DLP classification is a mature, separately licensed
 * category. A caller who needs it runs it and hands the result here.
 */

/**
 * The kind stamped on every manifest.
 *
 * `PayloadKind` is the error tracker's seven and none of them is `'prompt'`.
 * Adding a member to a shared package for the sake of a consumer that did not
 * exist when it was written is a decision worth making deliberately, so the
 * interim is `'event'` and `PromptManifest`'s own two fields carry the
 * meaning.
 */
const KIND: PayloadKind = 'event';

/** Raised when a scrub could not establish what was in the payload. */
export class PromptScrubFailedError extends Error {
  /** The dotted path the prose pass failed at, when the failure had one. */
  readonly path: string | undefined;
  /** The constructor name of what was thrown, and nothing else from it. */
  readonly thrown: string;

  constructor(stage: string, path: string | undefined, thrown: string) {
    super(
      `scrubForPrompt: ${stage} failed${path === undefined ? '' : ` at '${path}'`} with ${thrown}. ` +
        'The payload was not scrubbed and has not been returned: a payload whose content could ' +
        'not be established must not be sent.'
    );
    this.name = 'PromptScrubFailedError';
    this.path = path;
    this.thrown = thrown;
  }
}

/**
 * Build a scrubber whose policy and content paths are resolved once.
 *
 * This is the form to use on a request path. Resolution walks and lowercases
 * every denied key and path, and an error tracker does that at install time
 * because the alternative is doing it on the error path. An LLM caller has no
 * install moment, so the factory is where the moment goes.
 *
 * @param options - Policy, content paths, and the optional content hook
 * @returns A scrubber that does no list arithmetic per call
 *
 * @throws ScrubPolicyError If the policy cannot be resolved. Thrown here,
 *         where the stack trace points at the caller's setup, rather than at a
 *         request six hours later.
 */
export function createPromptScrubber(options: PromptScrubOptions = {}): PromptScrubber {
  const policy = resolveScrubPolicy(mergeScrubPolicy({ denyKeys: LLM_DENY_KEYS }, options.policy));

  const contentPaths = new Set(
    (options.contentPaths ?? DEFAULT_CONTENT_PATHS).map((path) => path.toLowerCase())
  );

  const transform = options.transformContent;

  return <P>(payload: P): PromptScrubResult<P> => run(payload, policy, contentPaths, transform);
}

/**
 * Scrub one payload, resolving the policy as it goes.
 *
 * The convenience form, and correct for a script. On a server use
 * {@link createPromptScrubber}: this resolves the policy and the content paths
 * on every call.
 *
 * @param payload - The request body, which is not modified at any depth
 * @param options - Policy, content paths, and the optional content hook
 * @returns The scrubbed copy and the manifest
 *
 * @throws PromptScrubFailedError If the walk could not establish what was in
 *         the payload. This throws rather than returning a stub, which is
 *         where it parts from `scrub`'s `guardedScrub` deliberately: an error
 *         tracker's stub preserves the signal that an error occurred while
 *         dropping the payload, and a prompt has no equivalent. A stub prompt
 *         is a request that costs money and answers a question nobody asked,
 *         and the caller cannot tell it from a real one.
 */
export function scrubForPrompt<P>(
  payload: P,
  options: PromptScrubOptions = {}
): PromptScrubResult<P> {
  return createPromptScrubber(options)(payload);
}

/** One scrub, with the failure path that reports before it throws. */
function run<P>(
  payload: P,
  policy: ResolvedScrubPolicy,
  contentPaths: ReadonlySet<string>,
  transform: PromptScrubOptions['transformContent']
): PromptScrubResult<P> {
  const prose: ProseFindings = { positions: 0, handles: [], path: undefined };
  let stage = 'the structural walk';

  try {
    // Stages 1 and 2 are `scrub`'s walk, not a copy of it. Four corrections
    // were paid for in measurement there and a reimplementation would lose all
    // four: it uses `redactCopy` rather than `redactInStructure`, so an object
    // referenced twice stays one reference and symbol keys survive; it reads
    // the report off the original rather than the copy, so a marker sighting
    // means a marker arrived in the payload rather than being one this package
    // just wrote; it probes duck-type properties through a guarded read, so a
    // Proxy that throws on an unknown name does not take out the scrub; and it
    // treats a value that refuses enumeration as a leaf.
    const { payload: scrubbed, report } = scrubPayload(payload, policy, KIND);

    stage = 'the prose pass';
    visitProse(payload, scrubbed, '', contentPaths, transform, prose, new WeakSet());

    const manifest: PromptManifest = {
      ...report,
      handles: prose.handles,
      contentPositions: prose.positions,
    };

    reportScrub(policy, manifest);

    return { prompt: scrubbed as P, removed: manifest };
  } catch (error) {
    // Before the throw, and this package's job to do: `scrubPayload` does not
    // call `onScrub` at all, and in `scrub` only `guardedScrub` does, on the
    // never-throw path this function declines. An operator needs to see a
    // scrubber failing on every request of one shape, and a thrown error the
    // caller catches and retries is not that signal.
    const failure: PromptManifest = {
      ...failedReport(KIND, policy),
      handles: [],
      contentPositions: 0,
    };

    reportScrub(policy, failure);

    // The type only. Not the message, not the stack, and no `cause`: this is
    // the package that fails while holding the values, so its own error is a
    // leak position, and chaining the original would put the content back into
    // whatever reports the error.
    throw new PromptScrubFailedError(stage, prose.path, describeThrown(error));
  }
}

/** What the prose pass found, and where it was when it stopped. */
interface ProseFindings {
  positions: number;
  readonly handles: string[];
  /** The path last entered, so a failure can name it without carrying content. */
  path: string | undefined;
}

/**
 * The one extra pass, over the prose positions.
 *
 * Walks the copy and the original together for one reason: `redactCopy` builds
 * a fresh object or array for everything it descends into and returns the same
 * reference for everything it passes through, so `copy !== original` is an
 * exact test for "this node is ours to write to". Without it, a
 * `transformContent` result could be written into the caller's own object.
 */
function visitProse(
  original: unknown,
  copy: unknown,
  path: string,
  contentPaths: ReadonlySet<string>,
  transform: PromptScrubOptions['transformContent'],
  findings: ProseFindings,
  seen: WeakSet<object>
): void {
  if (copy === null || typeof copy !== 'object') {
    return;
  }

  // A shared reference reached a second time, or a cycle. Already visited, and
  // counting its positions again would inflate the manifest.
  if (seen.has(copy)) {
    return;
  }

  seen.add(copy);

  const entries = entriesOf(copy);

  if (entries === null) {
    return;
  }

  // Only a node the copy owns may be written to. A Date, a RegExp, a URL, an
  // Error or a typed array comes back by reference and belongs to the caller.
  const writable = copy !== original;
  const container = copy as Record<string, unknown>;

  for (const [key, child] of entries) {
    const childPath = path === '' ? key : `${path}.${key}`;

    findings.path = childPath;

    const childOriginal = childOf(original, key);

    if (typeof child === 'string') {
      if (pathDenied(childPath, contentPaths)) {
        // Counted whether or not it is prose the caller wrote, because the
        // useful reading of this number is "did the body match the shape I
        // think it has", and a body whose content is entirely wrapped values
        // is not a schema mismatch.
        findings.positions += 1;

        // A string in the copy where the original held something else is a
        // marker stage 1 wrote, not prose. It does not go to the hook: the
        // caller's contract is that whatever the hook returns is trusted
        // verbatim, and a hook that rewrites a marker into something
        // value-shaped is the one failure this package is strictest about.
        const fromStageOne = typeof childOriginal !== 'string';

        const replaced =
          transform === undefined || fromStageOne ? child : transform(child, childPath);

        if (typeof replaced !== 'string') {
          throw new TypeError(`transformContent must return a string, received ${typeof replaced}`);
        }

        if (writable && replaced !== child) {
          container[key] = replaced;
        }

        // After the transform, because the manifest describes the payload the
        // caller is handed rather than the one they passed in.
        collectHandles(replaced, findings.handles);
      }

      continue;
    }

    visitProse(childOriginal, child, childPath, contentPaths, transform, findings, seen);
  }
}

/** Own enumerable string keys, or `null` for a leaf, the way `scrub`'s walk decides it. */
function entriesOf(value: object): readonly (readonly [string, unknown])[] | null {
  try {
    return Object.entries(value);
  } catch {
    return null;
  }
}

/**
 * The node in the original corresponding to a key in the copy.
 *
 * The two line up because `redactCopy` copies own enumerable string keys and
 * nothing else. Where they do not, because the original refused the read, the
 * answer is `undefined`, which makes the child non-writable rather than
 * failing the pass.
 */
function childOf(original: unknown, key: string): unknown {
  if (original === null || typeof original !== 'object') {
    return undefined;
  }

  try {
    return (original as Record<string, unknown>)[key];
  } catch {
    return undefined;
  }
}

/** Handle-shaped tokens in one prose position, deduplicated in encounter order. */
function collectHandles(text: string, into: string[]): void {
  const pattern = handlePattern();
  let match = pattern.exec(text);

  while (match !== null) {
    if (!into.includes(match[0])) {
      into.push(match[0]);
    }

    match = pattern.exec(text);
  }
}

/**
 * Name what was thrown, without reading anything that could carry content.
 *
 * `name` on an arbitrary throw can be a getter, and the object may not be an
 * `Error` at all. Neither the message nor the stack is read: a message from a
 * failure inside a payload walk is exactly the place a fragment of the payload
 * would appear.
 */
function describeThrown(error: unknown): string {
  try {
    if (error instanceof Error && typeof error.name === 'string') {
      return error.name;
    }

    return `a thrown ${error === null ? 'null' : typeof error}`;
  } catch {
    return 'an unreadable throw';
  }
}
