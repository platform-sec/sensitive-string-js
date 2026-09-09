---
'@platform-sec/sensitive-string-http': patch
'@platform-sec/sensitive-string-data': patch
---

Stop paying for the failure the guards almost never find.

Both of these guards run on every request and every statement, and both did work whose only consumer
was a branch that does not fire. Neither change alters what is refused. What changes is what a clean
request costs to clear.

`assertNoMarker` percent-decoded every outgoing body before scanning it, which allocates two full
copies of the body: one from `replace(/\+/g, ' ')` and one from `decodeURIComponent`. A JSON body
contains neither `%` nor `+`, so `percentDecoded` is the identity on it and the decoded scan searches
a string identical to the one just searched. The decode is now skipped when the body holds neither
character, which is not a heuristic: with no `+` the replace has nothing to replace, with no `%` the
decode has nothing to decode, so `decoded !== wire` was already dead and the branch was unreachable.
Measured on Node 22.15.0 over a marker-free JSON body, median of seven rounds with each size in its
own process: 1 KB from 2.6 us to 105 ns, 16 KB from 34.9 us to 613 ns, 128 KB from 366 us to 5.9 us.
It is the only figure in this release that scales with payload size, so it is worth most to whoever
sends the largest bodies.

`+` is checked as well as `%`, and that half is load-bearing rather than defensive. A custom
`registerPolicy` redaction may contain a space, a form encoder puts that space on the wire as `+`,
and the resulting body carries the marker with no percent-escape anywhere in it. A check for `%`
alone would skip that body without looking at it, and a test now fails if the `+` is removed. A
second test compares the guard against an implementation that decodes unconditionally over a corpus
of bodies, so the equivalence is asserted rather than argued.

`findUnsafeParameter` walked the bound parameters through `parameterEntries`, which materialises a
`[string, unknown][]`, then carried a path string down the recursion and allocated a `WeakSet` per
container. On a bag with nothing wrong in it, which is every bag in a working application, all three
are built and discarded. The walk now reads the three bag shapes in place, builds the path only while
unwinding the branch that found something, and creates the cycle guard on the first descent rather
than on entry. Measured the same way: 5 scalars from 237 ns to 81 ns, 6 named scalars from 486 ns to
201 ns, 3 parameters with one nested array from 532 ns to 162 ns, a 4-level nesting from 1017 ns to
372 ns.

Whether that second one is worth having depends on the driver, and the doc comment says so rather
than quoting the ratio alone. Against a networked Postgres, 300 ns is invisible. Against in-process
`better-sqlite3`, where a small query is single-digit microseconds, it is a few percent of the
statement.

`parameterEntries` keeps its shape and its exported signature, but nothing calls it on the hot path
any more, so two walkers now read the same three bag shapes. They are held together by a test that
runs both over the same bags rather than by one calling the other, and adding a shape to one without
the other fails it.

Mutation testing found two coverage gaps that a green suite did not. Deleting the array segment from
the path on the unwind passed every test, because no fixture had an offence nested inside a container
inside an array, only inside an array directly. Removing the array cycle guard also passed, because
the only cycle in the fixtures was an object cycle. Both are now in the corpus, along with a mutual
cycle between an array and an object, and all six mutations of the new walk fail.
