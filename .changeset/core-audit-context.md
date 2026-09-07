---
'@platform-sec/sensitive-string-core': minor
'@platform-sec/sensitive-string-testing': minor
'@platform-sec/sensitive-string-prisma': patch
'@platform-sec/sensitive-string-typeorm': patch
---

Hand `auditReveal` the context the operation ran under.

The hook was called with the value and the operation and nothing else, so a sink could not tell which
unit of work a reveal belonged to. That is not a gap anyone works around cheaply: `sensitive-prisma`
tags each unwrap with the model, the operation and the argument path, and `sensitive-typeorm` tags
each column write with the table and the column, and both had to install their per-value context as
the ambient one around every single reveal so a sink could recover the tags from
`getCurrentRevealContext()` inside its own hook. One `AsyncLocalStorage` entry per sensitive value,
paid to move three strings.

`auditReveal(value, details, context)` now carries it. The context is the one passed to the call, or
the ambient one when the call passed none, which is the same context the policy's
`checkRevealAllowed` was asked to authorize, so an audit record and an authorization decision are
comparable after the fact. It is not always the context the hook was installed on: a reveal under a
`createChildContext()` is audited under the child, which is exactly what makes an integration's tags
reachable. Both packages now reveal plainly, and the entry went with the workaround.

The argument is typed as `AuditContext`: `name`, `reason` and `tags`, and no `auditReveal`, since the
sink reading it is that hook. The narrowing is in the type and not in a copy, so a sink may compare
the context by identity and an audited reveal allocates nothing; `tags` is the caller's own object,
shared by every reveal under the context, so a sink copies out what it means to keep rather than
writing to it.

A hook written with two parameters is unaffected, in types and at runtime. Code that calls a
context's `auditReveal` itself must pass the third argument; the only such caller in this repository
was the worker handoff's hook forwarder, which now passes the receiving context through so a
forwarded sink sees the work the sender named.

In `sensitive-string-testing`, `AuditCall` gains `context` and `AuditEntry.contextName` is read from
what core reports rather than from the log's own name, so an entry made under a nested child is
recorded under the child. The recorded context is a one-level copy: a record pointing at the live
mock context would close a cycle through `calls` that `JSON.stringify` could not walk.
