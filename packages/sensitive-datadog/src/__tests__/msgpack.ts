/**
 * Enough msgpack to read a `dd-trace` v0.4 trace payload.
 *
 * The agent ships its own encoder rather than depending on one, so the suite
 * needs its own decoder to read what actually went out. Decoding the real
 * bytes rather than intercepting the formatted spans is the point: it is the
 * only way to see what the encoder does, and the encoder is a second,
 * independent filter. `#encodeMetaEntries` skips any entry whose value is not
 * a string or a number, so an object that somehow reached `meta` is dropped at
 * the msgpack boundary rather than encoded. That is stricter than
 * `JSON.stringify`, not looser, which is the opposite of what the error
 * tracking design assumed.
 *
 * Only the types the v0.4 encoder emits are implemented. An unknown byte
 * throws rather than being skipped, so a format change is a loud failure.
 */

/** Decode one msgpack value from a buffer. */
export function decodeMsgpack(buffer: Buffer): unknown {
  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  const decoder = new TextDecoder();
  let at = 0;

  function read(): unknown {
    const byte = view.getUint8(at);
    at += 1;

    if (byte <= 0x7f) {
      return byte;
    }

    if (byte >= 0xe0) {
      return byte - 0x100;
    }

    if ((byte & 0xf0) === 0x80) {
      return map(byte & 0x0f);
    }

    if ((byte & 0xf0) === 0x90) {
      return array(byte & 0x0f);
    }

    if ((byte & 0xe0) === 0xa0) {
      return str(byte & 0x1f);
    }

    return wide(byte);
  }

  function wide(byte: number): unknown {
    switch (byte) {
      case 0xc0:
        return null;
      case 0xc2:
        return false;
      case 0xc3:
        return true;
      case 0xc4:
        return bin(u8());
      case 0xc5:
        return bin(u16());
      case 0xc6:
        return bin(u32());
      case 0xca:
        return f32();
      case 0xcb:
        return f64();
      case 0xcc:
        return u8();
      case 0xcd:
        return u16();
      case 0xce:
        return u32();
      case 0xcf:
        return u64();
      case 0xd0:
        return i8();
      case 0xd1:
        return i16();
      case 0xd2:
        return i32();
      case 0xd3:
        return i64();
      case 0xd9:
        return str(u8());
      case 0xda:
        return str(u16());
      case 0xdb:
        return str(u32());
      case 0xdc:
        return array(u16());
      case 0xdd:
        return array(u32());
      case 0xde:
        return map(u16());
      case 0xdf:
        return map(u32());
      default:
        throw new Error(`unsupported msgpack byte 0x${byte.toString(16)} at offset ${at - 1}`);
    }
  }

  function u8(): number {
    const value = view.getUint8(at);
    at += 1;

    return value;
  }

  function u16(): number {
    const value = view.getUint16(at);
    at += 2;

    return value;
  }

  function u32(): number {
    const value = view.getUint32(at);
    at += 4;

    return value;
  }

  function u64(): string {
    const value = view.getBigUint64(at);
    at += 8;

    // As a string: a trace id does not survive `Number`, and every consumer
    // here compares or prints it.
    return value.toString();
  }

  function i8(): number {
    const value = view.getInt8(at);
    at += 1;

    return value;
  }

  function i16(): number {
    const value = view.getInt16(at);
    at += 2;

    return value;
  }

  function i32(): number {
    const value = view.getInt32(at);
    at += 4;

    return value;
  }

  function i64(): string {
    const value = view.getBigInt64(at);
    at += 8;

    return value.toString();
  }

  function f32(): number {
    const value = view.getFloat32(at);
    at += 4;

    return value;
  }

  function f64(): number {
    const value = view.getFloat64(at);
    at += 8;

    return value;
  }

  function str(length: number): string {
    const value = decoder.decode(new Uint8Array(buffer.buffer, buffer.byteOffset + at, length));
    at += length;

    return value;
  }

  function bin(length: number): Buffer {
    const value = buffer.subarray(at, at + length);
    at += length;

    return value;
  }

  function array(length: number): unknown[] {
    const out: unknown[] = [];

    for (let index = 0; index < length; index += 1) {
      out.push(read());
    }

    return out;
  }

  function map(length: number): Record<string, unknown> {
    const out: Record<string, unknown> = {};

    for (let index = 0; index < length; index += 1) {
      out[String(read())] = read();
    }

    return out;
  }

  return read();
}
