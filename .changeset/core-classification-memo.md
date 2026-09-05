---
'@platform-sec/sensitive-string-core': patch
---

Reuse the compiled form of a classification spec instead of rebuilding it per call.

`classifyField` compiles the spec it is handed, which means building a Map, validating every class
and recompiling every rule's `RegExp`, and it did that on every call. Over a payload of five keys it
measured 4339ns against 281ns for the same work through a compiled classification held across the
loop. The gap is the whole reason `compileClassification` is exported, and it is not a gap a caller
should have to know about to avoid.

`compileClassification` now memoizes per spec object in a `WeakMap`. On its own it went from 769ns
to 17ns, `classifyField` on one key from 868ns to 66ns, and over five keys from 4339ns to 281ns. The
entry is held only as long as the spec object is, so a spec built per request is collected with it.

One consequence worth stating, since it is observable. Reuse goes by object identity, so the same
spec object hands back the same compiled form, two equal specs compile separately, and a spec
mutated after it has been classified with keeps the form it compiled to the first time. A
`ClassificationSpec` is `readonly` throughout its type, so mutating one was never supported, but the
old behaviour would have picked the change up and the new one does not. All three cases are covered
by tests.
