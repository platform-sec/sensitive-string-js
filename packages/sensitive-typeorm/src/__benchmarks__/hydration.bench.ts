/**
 * What wrapping a row costs, by classified-column count.
 *
 * The comparison the design's release gate wants: an ORM allocates one instance
 * per classified field per row, for every row of every query, and this is the
 * only place that cost is visible. The control in each group is the same query
 * against the same in-memory database with no transformer anywhere, which is
 * the most hostile comparison available: it is the driver's own row parsing
 * with no network in it at all. A query against a real database has a round
 * trip that dwarfs the difference.
 *
 * Read these as ratios within a `describe` group and not as absolutes, per the
 * repository's convention. Vitest ranks within a group and prints the slowest
 * as a multiple of the fastest, and that ratio is the part that survives being
 * measured on a different machine.
 *
 * One thing this file cannot do, and the design document learned the hard way:
 * `vitest bench` runs each `bench` to completion in turn rather than
 * interleaving them, so a machine whose load drifts across a group attributes
 * the drift to whichever benchmark ran while it drifted. That is how a
 * measurement of six wrapped columns once came out faster than the unwrapped
 * control. Take a before-and-after on one quiet machine with
 * `vitest bench --outputJson` and `--compare`, and distrust a single run.
 */

import { DataSource, EntitySchema } from 'typeorm';
import { bench, describe } from 'vitest';
import { sensitiveColumn } from '../transformer.js';

const ROWS = 200;
const COLUMNS = 6;
const VALUE = 'a-value-of-a-plausible-length-for-a-column';

/** A `DataSource` over one table of six text columns, `classified` of them wrapped. */
async function makeSource(classified: number): Promise<DataSource> {
  const columns: Record<string, unknown> = {
    id: { type: Number, primary: true, generated: true },
  };
  for (let i = 0; i < COLUMNS; i += 1) {
    columns[`c${i}`] =
      i < classified
        ? {
            type: String,
            transformer: sensitiveColumn('sensitive', { table: 'rows', column: `c${i}` }),
          }
        : { type: String };
  }
  const Row = new EntitySchema({ name: 'Row', tableName: 'rows', columns: columns as never });
  const ds = new DataSource({
    type: 'better-sqlite3',
    database: ':memory:',
    synchronize: true,
    entities: [Row],
  });
  await ds.initialize();

  const values: Record<string, string> = {};
  for (let i = 0; i < COLUMNS; i += 1) values[`c${i}`] = VALUE;
  // Written raw, so seeding costs the same for every arm and the write path is
  // not part of what the read benchmark measures.
  const placeholders = Array.from({ length: COLUMNS }, () => '?').join(', ');
  const names = Array.from({ length: COLUMNS }, (_, i) => `"c${i}"`).join(', ');
  for (let r = 0; r < ROWS; r += 1) {
    await ds.query(`INSERT INTO "rows"(${names}) VALUES (${placeholders})`, Object.values(values));
  }
  return ds;
}

describe(`hydrating ${ROWS} rows of ${COLUMNS} columns`, () => {
  let control: DataSource;
  let one: DataSource;
  let three: DataSource;
  let six: DataSource;

  // Built in `setup` rather than `beforeAll`, which Vitest ignores for
  // benchmarks: the options a `bench` takes are the Bench library's, and
  // `setup`/`teardown` are its names for the same idea.
  const build = async () => {
    control ??= await makeSource(0);
    one ??= await makeSource(1);
    three ??= await makeSource(3);
    six ??= await makeSource(6);
  };

  bench(
    'no classified columns (control)',
    async () => {
      await control.getRepository('Row').find();
    },
    { setup: build }
  );

  bench(
    '1 of 6 classified',
    async () => {
      await one.getRepository('Row').find();
    },
    { setup: build }
  );

  bench(
    '3 of 6 classified',
    async () => {
      await three.getRepository('Row').find();
    },
    { setup: build }
  );

  bench(
    '6 of 6 classified',
    async () => {
      await six.getRepository('Row').find();
    },
    { setup: build }
  );
});

describe('one write, by operation', () => {
  let ds: DataSource;
  const build = async () => {
    ds ??= await makeSource(2);
  };
  bench(
    'insert()',
    async () => {
      await ds
        .getRepository('Row')
        .insert({ c0: VALUE, c1: VALUE, c2: VALUE, c3: VALUE, c4: VALUE, c5: VALUE });
    },
    { setup: build }
  );

  bench(
    'save() on an unchanged entity',
    async () => {
      // Two reveals per classified column and no UPDATE issued. The gap
      // against insert() is the audit-volume recommendation in the README,
      // measured rather than asserted.
      const found = await ds.getRepository('Row').findOneByOrFail({ id: 1 });
      await ds.getRepository('Row').save(found);
    },
    { setup: build }
  );
});

describe('the parameter guard', () => {
  let guarded: DataSource;
  let plain: DataSource;
  const build = async () => {
    if (guarded === undefined) {
      guarded = await makeSource(0);
      const { guardParameters } = await import('../guard.js');
      guardParameters(guarded);
    }
    plain ??= await makeSource(0);
  };

  bench(
    'a statement with 6 parameters, unguarded (control)',
    async () => {
      await plain.query('SELECT ?, ?, ?, ?, ?, ?', [1, 2, 3, 4, 5, 6]);
    },
    { setup: build }
  );

  bench(
    'the same statement, guarded',
    async () => {
      await guarded.query('SELECT ?, ?, ?, ?, ?, ?', [1, 2, 3, 4, 5, 6]);
    },
    { setup: build }
  );
});
