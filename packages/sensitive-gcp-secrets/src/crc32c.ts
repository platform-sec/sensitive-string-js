/**
 * CRC32C (Castagnoli), because Google ships an integrity check with the secret
 * and a check nobody runs is decoration.
 *
 * `accessSecretVersion` returns `payload.dataCrc32c` alongside the bytes, and
 * Google's own guidance is to verify it. The verification runs on the bytes
 * before anything is wrapped, which is what keeps it from being a reveal: at
 * that point the value is still a buffer this package is decoding, not a
 * `SensitiveString` somebody would have to reveal to check.
 *
 * Implemented here rather than taken from a dependency because this package has
 * no third-party runtime dependencies, and 40 lines of table-driven CRC is a
 * poor reason to break that. The polynomial is the reflected Castagnoli
 * constant, 0x82F63B78, and the suite pins the standard `"123456789"` vector.
 */

const POLYNOMIAL = 0x82f6_3b78;

/** Built once. 256 entries, one per input byte. */
const TABLE = ((): Uint32Array => {
  const table = new Uint32Array(256);

  for (let index = 0; index < 256; index += 1) {
    let value = index;

    for (let bit = 0; bit < 8; bit += 1) {
      value = value & 1 ? (value >>> 1) ^ POLYNOMIAL : value >>> 1;
    }

    table[index] = value >>> 0;
  }

  return table;
})();

/** The CRC32C of a buffer, as an unsigned 32-bit number. */
export function crc32c(bytes: Uint8Array): number {
  let crc = 0xffff_ffff;

  for (const byte of bytes) {
    // `!` is not needed: the index is masked to 0..255, which is always in
    // range for a 256-entry table, but `noUncheckedIndexedAccess` cannot see
    // that. The fallback is unreachable and costs nothing.
    crc = ((crc >>> 8) ^ (TABLE[(crc ^ byte) & 0xff] ?? 0)) >>> 0;
  }

  return (crc ^ 0xffff_ffff) >>> 0;
}

/**
 * The checksum as the API delivers it.
 *
 * `dataCrc32c` is an int64 on the wire, so gax hands it over as a number, a
 * `Long`, or a decimal string depending on how the value was decoded and how
 * large it is. All three mean the same integer, and a comparison that only
 * handled one of them would silently skip verification for the other two, which
 * is the worst outcome available: the check appears to run and never fails.
 */
export function toChecksum(value: unknown): number | undefined {
  if (typeof value === 'number') {
    return Number.isFinite(value) ? value >>> 0 : undefined;
  }

  if (typeof value === 'string') {
    const parsed = Number(value);

    return Number.isFinite(parsed) ? parsed >>> 0 : undefined;
  }

  if (typeof value === 'object' && value !== null) {
    // A protobufjs `Long`, which is `{ low, high, unsigned }`. A CRC32C fits in
    // the low word, and a high word that is neither 0 nor a sign extension is
    // not a CRC32C at all.
    const long = value as { low?: unknown; high?: unknown; toString?: unknown };

    if (typeof long.low === 'number' && (long.high === 0 || long.high === -1)) {
      return long.low >>> 0;
    }

    // A `Long` that hides its words behind accessors still stringifies to its
    // decimal value. `String(value)` would reach `Object.prototype.toString`
    // for anything else and produce `[object Object]`, so the own method is
    // called directly and only when it is there.
    const stringify = long.toString;

    if (typeof stringify === 'function') {
      const parsed = Number((stringify as () => string).call(value));

      return Number.isFinite(parsed) ? parsed >>> 0 : undefined;
    }
  }

  return undefined;
}
