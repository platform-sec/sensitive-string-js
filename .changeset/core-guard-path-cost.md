---
'@platform-sec/sensitive-string-core': patch
---

Stop paying for a clock read, an ISO rendering and a Set on paths that do not need them.

Three costs found by the benchmark suite and attributed against the primitives underneath them, all
measured on this machine at Node 22.15.0 with the harness overhead subtracted.

`#expiredDeadline` read `Date.now()` before looking at whether any state carried a deadline, so a
value that cannot expire paid for a clock read on every reveal, comparison, transform, mask and
serialize. `Date.now()` measured 82ns here, against 141ns for the whole of `reveal()`: the gate spent
more on asking the time than on everything else together. The loop now reads the clock lazily, at
most once, and only when a state actually has a deadline. `reveal()` on a value with no deadline
went from 141ns to 40ns, and `equals()` on a `sensitive` value from 160ns to 75ns.

`serialize()` called `new Date(deadline).toISOString()` on every call, which measured 1060ns on its
own, more than the rest of the method put together. The rendering is memoized by the deadline it
renders, so a renewal misses and re-renders on its own, and the memo is discarded once it passes 256
entries so a service with many distinct deadlines cannot grow it without bound. A deadline is a
number that already travels on the wire in exactly this form, so nothing secret is held there.
`serialize()` on an expiring value went from 1393ns to 153ns.

Deriving from a single source rebuilt the state list through a `Set` and an `Array.from`, when the
source's own list is already what the derivative needs. `#states` is assigned once and never
mutated, and the state objects are shared between derivatives by design, so the single-source case
now reuses it. `substring()` went from 273ns to 96ns and `concat()` from 359ns to 259ns.

No behaviour changes. The expiry gate, the wire format and the deadline a derivative inherits are
all unchanged, and the suite that covers them is unchanged too. Two cases were added to the wire
format tests: that a renewed value serializes its new deadline rather than the one it first
rendered, and that more distinct deadlines than the memo holds each serialize correctly across two
passes. Both fail against a memo keyed wrongly.
