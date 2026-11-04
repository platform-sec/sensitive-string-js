# @platform-sec/sensitive-string-kdf

## 0.2.0

### Minor Changes

- f8377ff: A `kdf` package: password hashing with Argon2, bcrypt or scrypt, and the stored hash wrapped as a
  credential.

  ROADMAP 1.2, the half that cannot live in `core`. Argon2 and bcrypt are native modules and `core`
  has no runtime dependencies (rule R7), so `hashForStorage` and `verifyHash` ship here, as free
  functions rather than as methods, with both modules optional peer dependencies. An application that
  installs neither still hashes with scrypt, which `node:crypto` computes, and that is what makes the
  package usable in an environment where a native build is not an option.

  Reading a protected password goes through `core`'s ordinary gate, so hashing one appears in an audit
  log as the exposure it is and a revoked password cannot be hashed. The hash itself is a fresh
  `credential` that does not inherit the password's deadline or reveal budget. It is the one place in
  this library where a derived value does not carry its source's constraints, stated here because it
  is a deviation and not an oversight: a stored hash has to outlive the password and be read on every
  login, and a salted, memory-hard hash is not a reversible copy of the value the way a fast digest of
  a guessable one is. `core`'s `hash()` inherits for exactly that reason. The case where the reasoning
  is thin is a secret an attacker can enumerate outright, a four-digit PIN, and no KDF rescues that.

  Three things the design sketch did not have. bcrypt hashes the first 72 bytes of a password and
  silently ignores the rest, so two passwords sharing a 72-byte prefix verify against each other's
  hash; this refuses the longer password on both the hashing and the verifying side, counting bytes
  rather than characters, because an error at registration is a bug report and a silent truncation is
  an authentication bypass nobody finds. The scrypt PHC string records `ln`, the base-two logarithm of
  the cost, rather than the `N=16384` the sketch wrote, which is what the format actually specifies
  and what makes a hash written here readable by something that is not this package. And a stored
  string is untrusted input, since it arrives from a database column: its parameters are bounded on
  the way back in, or one row asking for `ln=22, r=64, p=16` is a denial of service.

  Every parameter has a floor as well as a default, and a value below it is refused rather than
  quietly raised. bcrypt's rounds also has a ceiling, because it is an exponent: 20 is around thirty
  seconds per hash and 31, which bcrypt accepts, is measured in weeks.

  `needsRehash` is the other half of that. Verification reads the parameters out of the stored string,
  so a password hashed years ago keeps verifying forever; this is how an application notices that it
  should not, and rehashes at the one moment it holds the plaintext. It reports weaker, never
  different: rolling a configuration back must not rehash a fleet of passwords down to the lower
  setting, though a different algorithm family always reports, since that is the migration it exists
  for. It hashes nothing and loads no native module, which lets it answer for an algorithm the process
  cannot compute, and it cost one bug worth recording: the specification lists Argon2's parameters as
  `m,t,p` and the `argon2` package writes `m,p,t`, so a parser written from the format matches no hash
  in production. The parameters are read as a list rather than in a fixed order.

  Verification takes the algorithm and parameters from the stored hash rather than from anything
  configured today, so a store hashed under weaker parameters keeps verifying while new passwords use
  stronger ones. A wrong password answers `false`; a stored hash that cannot be read throws, because a
  corrupted column reported as a failed login is an account nobody can sign in to and nobody can
  explain. The string it could not read is never repeated in the message.

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
- Updated dependencies [29c6f87]
  - @platform-sec/sensitive-string-core@0.6.0
