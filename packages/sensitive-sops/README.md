# @platform-sec/sensitive-string-sops

SOPS documents as a `SecretSource`: the classification is derived from the ciphertext rather than
restated by hand, the age identity reaches the child process's environment and never the parent's,
and the parser that reports the offending line only ever sees encrypted values.

## Installation

```bash
pnpm add @platform-sec/sensitive-string-sops
```

## Requirements

- Node.js 22.12+
- `@platform-sec/sensitive-string-core` (peer dependency)
- `@platform-sec/sensitive-string-secrets` (peer dependency)
- **The `sops` binary**, on `PATH` or named by `binary`
- `yaml` (optional peer, only for deriving from a YAML document)
- `age-encryption` (optional peer, only for `decryptAge`)

A binary prerequisite is not expressible in `package.json`, so it is here, in the package
description, and in the error the constructor's version check produces.

## Why it shells out

This package runs the `sops` binary and does not implement SOPS.

A pure-JavaScript implementation would be a security-critical reimplementation of a format with five
key backends, and getting the AES-GCM handling or the MAC verification subtly wrong is a failure
this library would be actively responsible for. Shelling out means the decryption is done by the
tool the file was produced with.

`decryptAge` is the deliberate exception, and the split is the point: a format with one cipher and a
maintained TypeScript implementation by age's own author is safe to do in process; a format with
five key backends and a canonical Go implementation is not.

## Usage

```typescript
import { parse } from 'yaml';
import { SopsSecretSource } from '@platform-sec/sensitive-string-sops';

const sops = new SopsSecretSource({
  ageKey: ageIdentity,        // SensitiveString<'credential'>
  yamlParse: parse,
  onLoad: (event) => audit.info('secret.load', event),
});

const secrets = await sops.getDerived('/etc/app/secrets.enc.yaml');

secrets.fields.get('database.password');   // SOPS encrypted it
secrets.plain.get('database.host');        // SOPS did not, so it is not wrapped
```

The version check runs at construction, so a missing or unrunnable binary fails where somebody can
read it rather than at the first decrypt in the middle of a request. `await sops.version()` is how
an application waits for it at boot.

### Classification derived from the ciphertext

SOPS already recorded which values are secret. An encrypted leaf is the literal string
`ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]`, and anything SOPS left alone is a value somebody
decided did not need encrypting.

Deriving from that is better than asking the caller to restate it, because a hand-written spec
drifts from the file and the drift is silent in the direction that matters: a newly encrypted field
the spec does not mention. The other source of the same information is `.sops.yaml`'s
`encrypted_regex` and friends, and reading the ciphertext is preferred because it is what was
actually encrypted rather than what the rules were supposed to encrypt. The two disagree whenever
the rules changed after the file was written.

`getDerived` needs no `fallback`, unlike every other `getAll` source, because the derivation
supplies one per key. Calling `getAll` with an explicit spec turns the derivation off and the
requirement back on.

```typescript
await sops.getDerived(path, {});                                  // derived
await sops.getAll(path, { rules: [...], fallback: 'plain' });      // explicit, no derivation
await sops.deriveFor(path);                                       // just the spec, to look at
```

Rules can promote a derived class. Demoting one needs `derive: { allowDemotion: true }`, because a
spec quietly loosening what SOPS encrypted is the drift this derivation exists to prevent.

An operator who left a genuine secret unencrypted in the file gets it classified `plain`. That is a
true report of what the file says, and an argument for a lint rule rather than for a different
default.

### The parser that can leak only ever sees ciphertext

Deriving means reading the **encrypted** file, which for the common case is YAML and needs a YAML
parser, and YAML parsers report the offending line in their errors. That is safe here and only here:
the encrypted file's values are ciphertext, so a parse error on it discloses ciphertext and key
names.

The decrypted document is JSON, because the decrypt runs with `--output-type json`, and it goes
through the shared decode guard. Keeping the YAML parser on the ciphertext side is an invariant with
a test rather than a comment.

### The decryption key

```typescript
new SopsSecretSource({ ageKey });   // SensitiveString<'credential'>
new SopsSecretSource({});           // KMS: ambient cloud credentials do the work
```

The age identity is a credential, so it is a `SensitiveString` like everything else this package
produces. The value that unlocks everything else should not be the one plain string in the
configuration.

It is revealed per decrypt, under this package's own reveal context, and placed in the **child's**
environment as `SOPS_AGE_KEY`, specifically not the parent's:

- The parent's environment is visible in `/proc/<pid>/environ` for the life of the process, is
  copied into every other child it spawns, and is what an error tracker collects when it captures
  the environment.
- The child's is visible in `/proc/<child pid>/environ` to the same user, for as long as the decrypt
  takes, and then the process is gone.

Neither is private against a local attacker with the same uid. The child's is the better of the two
because it is bounded in time and never touches disk. Writing the key to a `0600` temp file for
`SOPS_AGE_KEY_FILE` was rejected: it trades a short-lived memory exposure for a filesystem artifact
that survives a crash.

The suite asserts the parent's `process.env` never gains `SOPS_AGE_KEY`, on the success path and on
the failure path, because a cleanup that only runs on success is the usual shape of that bug.

### stderr on a failure

```typescript
new SopsSecretSource({ ageKey, includeStderr: false });   // default is true
```

A decrypt failure is almost always a key or configuration problem and the binary's stderr is the
whole diagnosis, so it is attached to the error by default. That is a deliberate exception to the
caution the rest of this row shows about provider error text, and it rests on `sops` failing before
it produces plaintext.

That assumption is now measured rather than asserted. See the table below, including the part that
is not about plaintext: stderr also names the recipients' public keys and the local paths sops
probed for identities, which on a developer machine includes a home directory.

### No write path

Writing a SOPS document means re-encrypting it for every recipient in the `sops` block, which is the
binary's job and involves key material for people who are not running this process. This package
offers no `put`; use `sops -e` and `sops updatekeys`. The shared layer's marker guard therefore does
not apply here, which is worth saying explicitly so nobody concludes it was forgotten.

### Watching

```typescript
const watcher = sops.watch(path, {}, { onChange: (next) => pool.reconfigure(next) });
```

A SOPS file has no expiry; it is replaced by a deployment, which makes it a watcher source. A
re-read is a full decrypt, so the debounce matters more here than anywhere else: an undebounced
watcher on a file replaced by rename spawns several `sops` processes for one change.

### age on its own

```typescript
import { Decrypter } from 'age-encryption';
import { decryptAge } from '@platform-sec/sensitive-string-sops/age';

const secret = await decryptAge(ciphertext, {
  identity: ageIdentity,
  decrypter: new Decrypter(),
  label: 'webhook-key',
});
```

A single age-encrypted blob, with no SOPS document around it, needs no subprocess and no binary. It
lives behind its own entry point, so an application using only the SOPS path never loads it, and the
`Decrypter` is injected so this module imports nothing from the optional peer.

## Measured behaviour

All on `sops` 3.13.3, Linux, with an age identity, run by `src/__tests__/live.test.ts`.

| Question | Answer |
|---|---|
| Does sops write decrypted content to stderr on a failure path? | **No**, on the three paths tested: wrong identity, tampered ciphertext, and a file that is not a SOPS document |
| What else is on stderr? | The recipients' public age keys, and the local paths sops probed for identities, which included `/home/<user>/.ssh/id_rsa`. No values |
| What does a MAC failure say? | `Could not decrypt with AES_GCM: cipher: message authentication failed`, exit 25. No key name, no value |
| What does a wrong identity say? | `Failed to get the data key required to decrypt the SOPS file`, exit 128 |
| What does an absent file say? | `cannot operate on non-existent file "<path>"`, exit **100** |
| What does a non-SOPS file say? | `sops metadata not found`, exit 1 |
| What does an encrypted leaf look like? | `ENC[AES256_GCM,data:<base64>,iv:<base64>,tag:<base64>,type:str]`, with the `sops` block at the document root |

The absent-file row is why this table exists. An earlier version of this package matched on `no such
file or directory`, which is what its own stand-in binary printed and not what sops says, so
`getOptional` threw for every absent document. The check is now the filesystem's rather than the
binary's message, and the stand-in binary prints what the real one prints.

`includeStderr` stays on by default given those measurements, and the second row is the reason a
deployment might still turn it off.

## What this does not protect against

- **The stdout buffer.** The decrypted document is captured into a string, which is a copy of the
  whole plaintext that this package cannot clear. It is the largest uncollectable copy in this row.
- **The child's environment.** Bounded in time, but readable by the same uid while the decrypt runs.
- **Anything about the encrypted file at rest.** The classification derivation reports what SOPS
  encrypted; it does not encrypt anything.
- **A local attacker with the same uid**, which is the limit both `/proc/<pid>/environ` and the
  stdout buffer share.
- **Memory dumps and heap persistence before GC**, which is the library-wide limitation.

## License

MIT
