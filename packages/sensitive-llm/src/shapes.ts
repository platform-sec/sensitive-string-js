/**
 * Which dotted paths in a request body hold prose.
 *
 * Separate from `scrub.ts` on purpose. This is the one file whose contents are
 * claims about somebody else's schema, so keeping it in one place makes it
 * obvious what has to be rechecked when a provider ships a new version. The
 * scrubber itself knows nothing about any provider.
 *
 * ## Provenance, and what these paths are not
 *
 * Nothing here was measured against an installed SDK. This monorepo has no
 * provider SDK, not even as a devDependency, and the design's rule is that a
 * fixture written from a document tests the document rather than the provider.
 * So each entry below carries the schema it was written from and the flat
 * assertion that it is unverified, rather than a version number it would be
 * dishonest to print.
 *
 * The consequence for a caller: treat these as a starting point that covers
 * the common request shape, and supply `contentPaths` for anything else. A
 * path that does not match costs nothing except that `transformContent` is not
 * called there, and `PromptManifest.contentPositions` is how a caller notices.
 * A body whose shape has moved reports zero prose positions.
 *
 * None of this changes what the package protects. Content paths decide where a
 * caller's own `transformContent` hook runs and where handles are counted;
 * they are not a redaction list. Structural redaction and the key denylist run
 * over the whole payload regardless, which is the half of the leak this
 * package actually closes.
 */

/** A shipped set of content paths, with where it came from. */
export interface ContentPathShape {
  /** The provider and API surface these paths describe. */
  readonly schema: string;
  /**
   * Whether the paths were measured against an installed SDK.
   *
   * `false` on everything shipped today. See the module comment. A shape that
   * ever becomes `true` records the SDK version it was measured against in
   * `schema`.
   */
  readonly verified: false;
  readonly paths: readonly string[];
}

/**
 * Anthropic Messages API request body.
 *
 * `system` is a string or an array of text blocks. `messages[].content` is a
 * string or an array of blocks, and a `tool_result` block carries its own
 * `content`, which is again a string or an array of blocks. A tool's
 * `description` is prose the application wrote and is included for the same
 * reason a system prompt is.
 */
export const ANTHROPIC_MESSAGES: ContentPathShape = {
  schema: 'Anthropic Messages API request body',
  verified: false,
  paths: [
    'system',
    'system.*.text',
    'messages.*.content',
    'messages.*.content.*.text',
    'messages.*.content.*.content',
    'messages.*.content.*.content.*.text',
    'tools.*.description',
  ],
};

/**
 * OpenAI Chat Completions request body.
 *
 * `messages[].content` is a string or an array of parts, each with its own
 * `text`. A tool message's content is a string at the same path. The system
 * prompt is a message with `role: 'system'` rather than a field of its own,
 * which is the difference from the shape above that most affects a caller
 * porting paths between the two.
 */
export const OPENAI_CHAT_COMPLETIONS: ContentPathShape = {
  schema: 'OpenAI Chat Completions request body',
  verified: false,
  paths: ['messages.*.content', 'messages.*.content.*.text', 'tools.*.function.description'],
};

/**
 * OpenAI Responses API request body.
 *
 * `input` is a string or an array of items, and an item's `content` is a
 * string or an array of parts. `instructions` is the system prompt in this
 * surface.
 */
export const OPENAI_RESPONSES: ContentPathShape = {
  schema: 'OpenAI Responses API request body',
  verified: false,
  paths: [
    'instructions',
    'input',
    'input.*.content',
    'input.*.content.*.text',
    'tools.*.description',
  ],
};

/** Every shipped shape, by name. */
export const CONTENT_PATH_SHAPES = {
  anthropicMessages: ANTHROPIC_MESSAGES,
  openaiChatCompletions: OPENAI_CHAT_COMPLETIONS,
  openaiResponses: OPENAI_RESPONSES,
} as const satisfies Record<string, ContentPathShape>;

/**
 * The union of every shipped shape, which is what a scrubber uses by default.
 *
 * A union rather than a per-provider selection because the paths do not
 * collide in a way that costs anything: a path that names nothing in the body
 * at hand simply never matches. Selecting one shape is available and is worth
 * doing only when a caller wants `contentPositions` to mean "positions in the
 * shape I expect" rather than "positions anything recognized".
 */
export const DEFAULT_CONTENT_PATHS: readonly string[] = [
  ...new Set(Object.values(CONTENT_PATH_SHAPES).flatMap((shape) => shape.paths)),
];

/**
 * Envelope keys this package adds to `scrub`'s defaults.
 *
 * The bar is the one `scrub`'s own denylist sets: a name whose value is a
 * credential by construction rather than by convention. Provider-scoped API
 * key names clear it, because nothing but a key is ever called
 * `anthropic_api_key`. Nothing about the message content is here, and section
 * 2.2 of the design is why: the key is `content`, the key is always `content`,
 * and denying it denies the request.
 *
 * Every name here is one `scrub`'s defaults do not already carry, and
 * `shapes.test.ts` asserts that stays true. A list that quietly restated the
 * defaults would read as coverage this package added and would grow by
 * accident.
 */
export const LLM_DENY_KEYS: readonly string[] = [
  'anthropic_api_key',
  'anthropicApiKey',
  'openai_api_key',
  'openaiApiKey',
  'azure_openai_api_key',
  'google_api_key',
];
