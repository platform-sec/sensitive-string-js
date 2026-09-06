import { describe, expect, it } from 'vitest';
import { UnknownStoredHashError } from './errors.js';
import { encodeB64, encodeScryptPhc, parseScryptPhc } from './phc.js';
import { planStorageHash, type ScryptPlan } from './options.js';

const plan = planStorageHash({ algorithm: 'scrypt' }) as ScryptPlan;
const salt = Buffer.alloc(16, 7);
const hash = Buffer.alloc(64, 9);

describe('the scrypt PHC string', () => {
  it('records the exponent, not the cost, which is what PHC specifies', () => {
    expect(encodeScryptPhc(plan, salt, hash)).toMatch(/^\$scrypt\$ln=14,r=8,p=1\$/);
  });

  it('writes base64 without padding', () => {
    const encoded = encodeScryptPhc(plan, salt, hash);

    const [, , , saltSegment, hashSegment] = encoded.split('$');

    // The parameter segment spells `ln=14`, so the padding this is looking for
    // is only meaningful in the two base64 segments.
    expect(saltSegment).toBe(encodeB64(salt));
    expect(saltSegment).not.toContain('=');
    expect(hashSegment).not.toContain('=');
  });

  it('round-trips the parameters, the salt and the digest', () => {
    const parsed = parseScryptPhc(encodeScryptPhc(plan, salt, hash));

    expect(parsed.N).toBe(16_384);
    expect(parsed.r).toBe(8);
    expect(parsed.p).toBe(1);
    expect(parsed.salt.equals(salt)).toBe(true);
    expect(parsed.hash.equals(hash)).toBe(true);
  });

  describe('reading an untrusted string', () => {
    const rejected: [string, string][] = [
      ['empty', ''],
      ['another algorithm', '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA'],
      ['the cost written as N', '$scrypt$N=16384,r=8,p=1$c2FsdA$aGFzaA'],
      ['a missing segment', '$scrypt$ln=14,r=8,p=1$c2FsdA'],
      ['a salt that is not base64', '$scrypt$ln=14,r=8,p=1$not base64$aGFzaA'],
      ['a padded segment', '$scrypt$ln=14,r=8,p=1$c2FsdA==$aGFzaA'],
      ['an empty salt', '$scrypt$ln=14,r=8,p=1$$aGFzaA'],
      ['a parameter that is not a number', '$scrypt$ln=aa,r=8,p=1$c2FsdA$aGFzaA'],
      ['trailing content', '$scrypt$ln=14,r=8,p=1$c2FsdA$aGFzaA$extra'],
    ];

    for (const [name, stored] of rejected) {
      it(`refuses ${name}`, () => {
        expect(() => parseScryptPhc(stored)).toThrow(UnknownStoredHashError);
      });
    }

    it('refuses parameters that would allocate more memory than a hash may', () => {
      expect(() => parseScryptPhc('$scrypt$ln=22,r=64,p=16$c2FsdA$aGFzaA')).toThrow(
        UnknownStoredHashError
      );
    });

    it('accepts weaker parameters than it would produce, so an old store can be verified', () => {
      expect(parseScryptPhc('$scrypt$ln=10,r=8,p=1$c2FsdA$aGFzaA').N).toBe(1024);
    });

    it('never repeats the string it refused', () => {
      const stored = '$scrypt$ln=14,r=8,p=1$SALT_CANARY_NOT_BASE64$aGFzaA';

      try {
        parseScryptPhc(stored);
        expect.unreachable('parse must refuse');
      } catch (error) {
        expect(String(error)).not.toContain('SALT_CANARY');
      }
    });
  });
});
