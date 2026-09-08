---
'@platform-sec/sensitive-string-core': minor
---

Refuse BSON serialization instead of silently corrupting the document.

`SensitiveString` now has a `toBSON()` that throws `SensitiveBsonError`. This is a behavior change
for any application that persists an unrevealed instance to MongoDB today: that write starts
throwing. Throwing is the point, and what it replaces is worse.

Measured against `bson` 7.3.2 on Node 22.15.0. BSON honours `toBSON()` on a value and ignores
`toJSON()`, and the class had neither, so the encoder fell back to the instance's own enumerable
properties. Those are `klass` and `label`. A write of a classified token stored
`{ klass: 'credential', label: 'token' }` and dropped the value, with nothing thrown and nothing
logged, and the column looked populated. The same husk is produced for every value of a given class
and label, so a filter built from one instance matched a document written from another, which is an
authentication bypass rather than a storage bug. The refusal covers the top level of a document, a
subdocument and an array, and therefore every write path, every filter path, both bulk paths and the
raw driver, since all of them serialise through the same encoder.

`toJSON()` still redacts and still does not throw, because logging must not throw and a redacted log
line is useful. BSON is a persistence and matching format, where an unrevealed value has no useful
degraded outcome. Nothing but a BSON encoder calls `toBSON()`, so no other path pays for it.

Reveal at the write boundary, where the access is audited:

```ts
await users.updateOne({ _id }, { $set: { apiKey: token.reveal({ name: 'rotate-key' }) } });
```

Two alternatives were rejected. Returning the redaction marker keeps the corruption and makes every
classified path match the same constant, which is the same bypass with a different value in it.
Revealing under the ambient context makes writes work everywhere and quietly ships secrets into
filters, aggregation stages and every log line built from a command.
