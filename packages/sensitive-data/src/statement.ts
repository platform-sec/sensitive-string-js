/**
 * Deciding whether a statement's parameters might carry a classified value.
 *
 * No SQL is parsed here and none will be. The question is only whether a
 * classified name appears in the statement at all, which is answerable with a
 * scan and is wrong in a direction that costs a log entry rather than a secret.
 * A parser that is wrong once is worse than a rule that is coarse always.
 *
 * What this cannot do, and what every consumer README repeats: it cannot see
 * which parameter belongs to which column, so the censoring it drives is
 * positional-blind. A statement that touches a classified column loses all of
 * its string parameters. Recovering the mapping means parsing.
 */

/**
 * Every identifier in a statement, lowercased.
 *
 * Quoted in three dialects and bare, because the statement an ORM built quotes
 * its own identifiers and a statement a caller wrote by hand may not.
 */
const IDENTIFIER = /"([^"]+)"|`([^`]+)`|\[([^\]]+)\]|([A-Za-z_][A-Za-z0-9_$]*)/g;

/** The lowercased identifiers a statement mentions. */
export function identifiersIn(statement: string): Set<string> {
  const found = new Set<string>();
  if (typeof statement !== 'string' || statement === '') return found;

  for (const match of statement.matchAll(IDENTIFIER)) {
    const name = match[1] ?? match[2] ?? match[3] ?? match[4];
    if (name !== undefined) found.add(name.toLowerCase());
  }
  return found;
}

/**
 * Classified `table.column` paths, indexed by table, both halves lowercased.
 *
 * Only the exact entries of a specification can be enumerated. A rule is a
 * pattern with no list of names behind it, which is why
 * {@link touchesClassifiedColumn} takes a `classify` callback as well and
 * answers the rule half the other way round.
 */
export function indexClassifiedPaths(
  fields: Iterable<readonly [string, string]>
): Map<string, Set<string>> {
  const index = new Map<string, Set<string>>();

  for (const [path, klass] of fields) {
    if (klass === 'plain') continue;
    const at = path.lastIndexOf('.');
    if (at <= 0) continue;

    const table = path.slice(0, at).toLowerCase();
    const column = path.slice(at + 1).toLowerCase();
    const columns = index.get(table) ?? new Set<string>();
    columns.add(column);
    index.set(table, columns);
  }

  return index;
}

export interface TouchOptions {
  /**
   * Classified paths indexed by table, from {@link indexClassifiedPaths}. A
   * statement matches when it names both halves of one of them.
   */
  readonly paths?: ReadonlyMap<string, ReadonlySet<string>>;
  /**
   * Bare column names, matched wherever they appear. For a consumer that
   * registers columns rather than compiling a path specification, and for a
   * caller's own additions.
   */
  readonly columns?: ReadonlySet<string>;
  /**
   * The rule half of a specification: given one identifier, its class.
   *
   * Asked per identifier because a rule is a pattern, so there is no list to
   * intersect with. Anything answering something other than `'plain'` or
   * `undefined` counts. A specification with the usual `fallback: 'plain'` must
   * not answer the fallback here, or every statement in the process reports as
   * touching a classified column.
   */
  readonly classify?: (identifier: string) => string | undefined;
}

/**
 * Whether a statement mentions anything classified.
 *
 * Deliberately generous, and generous in the safe direction: a log entry that
 * loses its parameters is an inconvenience, one that keeps a password is an
 * incident. It answers yes for a statement that only joins the table, and yes
 * for an unrelated table whose column happens to share a classified name.
 */
export function touchesClassifiedColumn(statement: string, options: TouchOptions = {}): boolean {
  const { paths, columns, classify } = options;
  if (paths === undefined && columns === undefined && classify === undefined) return false;

  const identifiers = identifiersIn(statement);
  if (identifiers.size === 0) return false;

  if (paths !== undefined) {
    for (const [table, tableColumns] of paths) {
      // A schema-qualified key such as `public.users` is present when its last
      // segment is, since a statement writes the qualification separately.
      const tableName = table.slice(table.lastIndexOf('.') + 1);
      if (!identifiers.has(tableName)) continue;
      for (const column of tableColumns) {
        if (identifiers.has(column)) return true;
      }
    }
  }

  if (columns !== undefined) {
    for (const identifier of identifiers) {
      if (columns.has(identifier)) return true;
    }
  }

  if (classify !== undefined) {
    for (const identifier of identifiers) {
      const klass = classify(identifier);
      if (klass !== undefined && klass !== 'plain') return true;
    }
  }

  return false;
}

/** How much of a statement a refusal or a log line quotes. */
export const STATEMENT_LIMIT = 200;

/** A statement cut to {@link STATEMENT_LIMIT}, safe to call on anything. */
export function truncateStatement(statement: unknown): string {
  if (typeof statement !== 'string') return '(not a string)';
  return statement.length <= STATEMENT_LIMIT
    ? statement
    : `${statement.slice(0, STATEMENT_LIMIT)}...`;
}
