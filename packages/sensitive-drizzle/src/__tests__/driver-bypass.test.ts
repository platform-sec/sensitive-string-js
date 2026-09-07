import { SensitiveString } from '@platform-sec/sensitive-string-core';
import Database from 'better-sqlite3';
import mysql from 'mysql2';
import pgutils from 'pg/lib/utils.js';
import { describe, expect, it } from 'vitest';
import { CANARY } from './fixtures.js';

/**
 * What each driver does with a `SensitiveString` that reached it unmapped.
 *
 * This is the argument for the guard, kept as a test rather than as a sentence
 * in a README. Two of the three drivers accept the instance and run the
 * statement, which is why a refusal in front of them is the only thing that
 * turns the mistake into a failure the caller sees.
 *
 * None of these calls goes through this package. They are the drivers on their
 * own, which is exactly the situation `sensitiveLogger()` prevents.
 */

const value = new SensitiveString(CANARY, 'credential', 'token');

describe('an unwrapped instance at the driver', () => {
  it('better-sqlite3 throws, which is the only driver that fails loudly', () => {
    const db = new Database(':memory:');
    db.exec('create table t (v)');
    // The cast is the situation being described: a caller reaches this by
    // having an `any` between the value and the driver, which is what every
    // uncovered parameter path amounts to.
    const unmapped = value as unknown as string;
    expect(() => db.prepare('insert into t values (?)').run(unmapped)).toThrow(TypeError);
    db.close();
  });

  it('pg binds the redaction marker and reports success', () => {
    // `prepareValue` falls through to JSON.stringify for an object with a
    // toJSON, so the column ends up holding the marker with quotes around it.
    // The write succeeds. A later lookup by the same unwrapped value matches
    // the corrupted row, because both sides are the marker.
    const bound = pgutils.prepareValue(value);
    expect(bound).toBe('"[REDACTED:credential]"');
    expect(String(bound)).not.toContain(CANARY);
  });

  it('mysql2 escapes the enumerable properties into the statement', () => {
    // The class keeps its value in an ES private field, so what survives is the
    // two public fields. The statement is syntactically an assignment list and
    // matches nothing.
    const escaped = mysql.escape(value as unknown as Record<string, unknown>);
    expect(escaped).toBe("`klass` = 'credential', `label` = 'token'");
    expect(escaped).not.toContain(CANARY);
  });

  it('has exactly two enumerable own properties, which is what the other two saw', () => {
    expect(Object.keys(value)).toEqual(['klass', 'label']);
  });
});
