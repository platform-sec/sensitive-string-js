---
'@platform-sec/sensitive-string-scrub': minor
---

Opt-in value shape recognizers, and two exports the vendor packages needed.

`denyValues` takes pattern names or your own `RegExp` and is empty by default, which is the whole of
this layer's answer to whether a denylist should ever match on value shape. Everything else here
matches on key names and paths, because a scrubber that decides by looking at a string is a
classifier and is wrong some of the time, and the thing a user does about an error tracker that hides
values they needed is turn the scrubbing off entirely. A bearer token forwarded into a field nobody
named `authorization` is invisible to a key list, though, so the shapes ship: `jwt`, `bearer`,
`basicAuth`, `pemPrivateKey`, `awsAccessKeyId`, `githubToken`, `slackToken` and `openaiKey`.

Three rules every shipped pattern follows, each with a test over every pattern rather than an
argument. Anchored at both ends, including against a trailing newline, since JavaScript's `$` also
matches before a final line terminator. Linear time, checked against a pathological subject. And a
prefix a vendor issues rather than a shape that merely looks random. A caller's own `RegExp` is taken
as written with `g` and `y` stripped, because a sticky pattern carries `lastIndex` between payloads
and would match on one event and not the next.

`ScrubReport` gains `deniedValues`, which names the shapes that matched and never the values or the
paths they matched at: a path is a key name your application chose and is safe on its own, but a path
paired with a shape name is a map of where to look.

Also exported: `mergeReports`, which folds a second pass's findings into the report a seam will
publish while leaving the marker count alone, and `reportScrub`, so a vendor whose callback contract
is mutate-in-place runs its own guard and still swallows a throwing `onScrub` the same way.
