/**
 * One case of the process-memory probe, built in a child so the parent can scan
 * it.
 *
 * A scanner that reads its own `/proc/self/mem` copies every page it reads into
 * its own read buffer, finds the needle in the copy it just made, and inflates
 * the count by an amount that depends on where that buffer happens to sit. So
 * the measurement takes two processes: this one builds a representation and
 * idles, and the parent scans it.
 *
 * Two details make the counts readable, and both are load bearing:
 *
 * - The needle is 24 random bytes, and this process holds them in a `Buffer` in
 *   order to report them. **Every count therefore includes one hit that is the
 *   needle itself**, which the parent subtracts.
 * - Each case builds its own representation from a copy of those bytes, inside
 *   a function, so a local that the case is finished with is genuinely
 *   unreachable when the collector runs. A case that shared the needle's own
 *   `Buffer` or string object would measure one representation and report it as
 *   two.
 *
 * The hex line printed at the end is the needle in a form the parent can read
 * back. It is not the needle's bytes, so printing it adds no hit.
 *
 * Imports the package by name for the reason `worker-consume.mjs` does: this
 * runs under plain Node, so it needs the built `dist`, not the TypeScript.
 */
import { randomBytes } from 'node:crypto';
import { SensitiveString, setSealing } from '@platform-sec/sensitive-string-core';

const MODE = process.argv[2];

/**
 * The alphabet the needle is drawn from.
 *
 * Printable ASCII rather than raw random bytes, for two reasons that both have
 * to hold at once. `fromBuffer` refuses invalid UTF-8, and random bytes are not
 * valid UTF-8. And V8 stores a string whose characters all fit in one byte as
 * one byte each, so an ASCII needle's string form holds exactly the needle's
 * bytes; a two-byte string form would be a different sequence and the scan
 * would never see it.
 */
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

/** The needle, 32 ASCII bytes. Held for the life of the process to report it. */
const needle = Buffer.from(
  Array.from(randomBytes(32), (byte) => ALPHABET.charCodeAt(byte % ALPHABET.length))
);

/** Anything a case wants kept alive past its own frame. */
const held = [];

/** The needle as a fresh JavaScript string, one byte per character. */
function plaintextString() {
  return needle.toString('utf8');
}

/** The needle as a fresh `Buffer` the case owns. */
function plaintextBytes() {
  return Buffer.from(needle);
}

/** Collect hard enough that a released representation is actually gone. */
function collect() {
  for (let round = 0; round < 6; round++) {
    global.gc?.();
  }
}

const CASES = {
  /**
   * Nothing but the needle. The floor every other case is read against, and the
   * check that the scanner is not finding the needle in places nobody put it.
   */
  control() {},

  /** A plain string, live. What an unsealed value's storage looks like. */
  'live-string'() {
    held.push({ value: plaintextString() });
  },

  /**
   * The same string, dropped, with the source it came from zeroed. A heap
   * snapshot calls this absent. A dump is the one that is right about what is
   * still in the machine.
   */
  'dropped-string'() {
    let value = plaintextString();
    value = undefined;
    void value;
  },

  /** A live `Buffer`. */
  'live-buffer'() {
    held.push(plaintextBytes());
  },

  /** The same `Buffer`, zeroed. The only operation here that erases anything. */
  'zeroed-buffer'() {
    plaintextBytes().fill(0);
  },

  /** An unsealed value, live and never read. This is the library today. */
  unsealed() {
    held.push(new SensitiveString(plaintextString(), 'credential', 'probe'));
  },

  /**
   * A sealed value whose plaintext was never a JavaScript string, built through
   * `fromBuffer`, never revealed.
   */
  sealed() {
    held.push(SensitiveString.fromBuffer(plaintextBytes(), 'credential', 'probe'));
  },

  /** The same, then cleared, which zeroes the box. */
  'sealed-cleared'() {
    const value = SensitiveString.fromBuffer(plaintextBytes(), 'credential', 'probe');
    value.clear();
    held.push(value);
  },

  /** One string-returning reveal, dropped. */
  'sealed-reveal-1'() {
    const value = SensitiveString.fromBuffer(plaintextBytes(), 'credential', 'probe');
    void value.reveal().length;
    held.push(value);
  },

  /** A thousand of them. The regression this feature documents. */
  'sealed-reveal-1000'() {
    const value = SensitiveString.fromBuffer(plaintextBytes(), 'credential', 'probe');

    for (let read = 0; read < 1000; read++) {
      void value.reveal().length;
    }

    held.push(value);
  },

  /** A thousand byte-returning reveals, each zeroed by the caller. */
  'sealed-revealbytes-1000'() {
    const value = SensitiveString.fromBuffer(plaintextBytes(), 'credential', 'probe');

    for (let read = 0; read < 1000; read++) {
      value.revealBytes().fill(0);
    }

    held.push(value);
  },

  /**
   * A thousand comparisons against a string comparand, which is the archetypal
   * credential workload.
   *
   * The comparand is built once and hoisted out of the loop on purpose. Building
   * it inside would measure the harness rather than `equals()`: the first draft
   * did that and reported about 950 copies, all of them the loop's own
   * `toString()`, none of them anything `equals()` left behind.
   *
   * One copy therefore remains, which is the comparand itself, and it is the
   * caller's string rather than the library's. That is the same finding memory
   * hygiene reached from the other side: the library can only ever release the
   * library's copy.
   */
  'sealed-equals-string-1000'() {
    const value = SensitiveString.fromBuffer(plaintextBytes(), 'credential', 'probe');
    const guess = plaintextString();

    for (let attempt = 0; attempt < 1000; attempt++) {
      value.equals(guess);
    }

    held.push(value);
  },

  /**
   * A thousand comparisons of two sealed values, which is the path with no
   * plaintext string on either side.
   */
  'sealed-equals-sealed-1000'() {
    const value = SensitiveString.fromBuffer(plaintextBytes(), 'credential', 'probe');
    const guess = SensitiveString.fromBuffer(plaintextBytes(), 'credential', 'guess');

    for (let attempt = 0; attempt < 1000; attempt++) {
      value.equals(guess);
    }

    held.push(value, guess);
  },

  /**
   * The same thousand comparisons on unsealed values, for the contrast. Both
   * operands stay resident for the life of the values.
   */
  'unsealed-equals-1000'() {
    const value = new SensitiveString(plaintextString(), 'credential', 'probe');
    const guess = new SensitiveString(plaintextString(), 'credential', 'guess');

    for (let attempt = 0; attempt < 1000; attempt++) {
      value.equals(guess);
    }

    held.push(value, guess);
  },

  /**
   * A thousand reveals of an unsealed value, which return the same string
   * object every time. The control the sealed rows above are read against.
   */
  'unsealed-reveal-1000'() {
    const value = new SensitiveString(plaintextString(), 'credential', 'probe');

    for (let read = 0; read < 1000; read++) {
      void value.reveal().length;
    }

    held.push(value);
  },

  /** A sealed value built through the string constructor, for the contrast. */
  'sealed-from-string'() {
    setSealing({ sealByDefault: true });
    held.push(new SensitiveString(plaintextString(), 'credential', 'probe'));
  },
};

const build = CASES[MODE];

if (build === undefined) {
  process.stderr.write(`unknown case: ${String(MODE)}\n`);
  process.exit(2);
}

build();
collect();

process.stdout.write(`${needle.toString('hex')}\n`);

// Idle, so the parent has something to scan. The parent kills this.
setInterval(() => {}, 1 << 30);
