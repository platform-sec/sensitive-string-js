# @platform-sec/sensitive-string-newrelic

## 0.2.0

### Minor Changes

- 825ae8e: A New Relic integration, over the shared `@platform-sec/sensitive-string-scrub` layer. Everything
  below was measured on Node 22.15.0 against `newrelic` 14.3.10, driving the real agent in its
  serverless mode and decoding the gzipped payload it would otherwise post to the collector, plus
  direct calls into the shipped `AttributeFilter`, with a companion case requiring each position to
  leak once the configuration is removed.

  Like the Datadog half of this row, it does not close a default leak. At stock defaults the agent
  collects exactly six headers off a hard-coded list, none of them a credential, writes query
  parameters at destination `NONE`, and never reads the body. `allow_all_headers: true` is the opt-in
  that leaks, and it puts `authorization`, `cookie` and `request.headers.xApiKey` into the payload.

  There is nothing to wrap: the agent's 39 public API methods include no payload callback. So
  `sensitiveAgentConfig` is a pure function returning a configuration fragment, and two measured facts
  shape what it generates.

  Names are translated. The agent maps 50 known headers to camelCase and puts the rest through a
  fallback that title-cases every segment after the first, so an exclusion written as
  `request.headers.x-api-key` is silently ignored where `request.headers.xApiKey` is honoured. The map
  and the fallback are reproduced rather than imported, and a test pins the reproduction against the
  shipped agent on all 50 names plus a fixture set of shapes outside it. Because the fallback is not
  injective over casing, the generator emits every spelling it can derive rather than guessing which
  one will arrive.

  Rules are exact, and emitted in every casing. The agent compiles them into a `RegExp` with no `i`
  flag while `resolveScrubPolicy` lowercases, so generating from the resolved denylist alone excluded
  `accesstoken` and transmitted `accessToken`, and did the same for `refreshToken`, `sessionId`,
  `clientSecret`, `privateKey`, `confirmPassword`, `passwordConfirmation`, `secretKey`, `secretToken`
  and `idToken`. Each of those is in the shared list in that casing precisely because that is how it
  appears in a JavaScript payload, so the generator reads the source lists as written and emits both
  spellings. `filter.test.ts` pins all ten through the agent's own `AttributeFilter`.

  Rules are exact, not wildcards. The agent resolves include against exclude by match strength, so a
  wildcard exclusion is a default that any more specific include lifts, global or per destination,
  while an exact global exclusion is a floor nothing in the configuration surface can raise. A
  generator that emitted `request.headers.*` and called it done would produce a configuration that one
  later `include` line silently reopens. The one wildcard the package can emit is opt-in and documented
  as beatable, with the measured table in the README.

  `sensitiveAttributes` is the small opt-in beside it. The agent accepts only `string`, `number` and
  `boolean` and drops everything else with a debug log, so a wrapped value added as a custom attribute
  arrives as nothing rather than as its marker, and the obvious fix a hurried engineer reaches for is
  `reveal()`. It runs the shared walk and coerces what is left, so the marker arrives instead.

  The README states what no part of this package can reach, and names log forwarding first:
  `application_logging.enabled` and its `forwarding.enabled` both default to true, which is the one
  default-on egress in either agent of this row, and by the time a log record exists a revealed value
  is an ordinary string.

### Patch Changes

- Updated dependencies [3e054e2]
- Updated dependencies [49ad21c]
- Updated dependencies [200a5c9]
- Updated dependencies [b362710]
- Updated dependencies [aa609af]
- Updated dependencies [14ed60e]
- Updated dependencies [7de6338]
- Updated dependencies [e721fbd]
- Updated dependencies [a90709f]
- Updated dependencies [785c101]
- Updated dependencies [f8377ff]
- Updated dependencies [1eb5030]
- Updated dependencies [dfe8ae4]
- Updated dependencies [342f7e4]
- Updated dependencies [1c87ee4]
- Updated dependencies [7de3033]
- Updated dependencies [98fd326]
- Updated dependencies [f1d6d96]
- Updated dependencies [5950b87]
- Updated dependencies [b92ff33]
- Updated dependencies [dbb643a]
- Updated dependencies [59ace7a]
- Updated dependencies [f67efd7]
- Updated dependencies [48f6213]
- Updated dependencies [29c6f87]
  - @platform-sec/sensitive-string-core@0.6.0
  - @platform-sec/sensitive-string-scrub@0.2.0
