/**
 * Recognising a call to a logger.
 *
 * Two rules ask the same question. `no-log-reveal` asks it of a call's
 * arguments, `prefer-safe-log` of their types, and neither is useful if they
 * disagree about what a logger is: a project that configures its own logger
 * name for one and finds the other still blind to it has been given two rules
 * where it configured one. The vocabulary and the matcher live here so there
 * is one answer.
 */
import { calleeChainNames, calleeOf, identifierName } from './ast.js';
import type { AstNode } from './types.js';

/**
 * Method names on a logger, plus `write`.
 *
 * `write` is here for `process.stdout.write(secret.reveal())`, which leaks
 * exactly what `console.log` leaks and is the first thing reached for when a
 * log line needs no newline. It only ever matches alongside a name from
 * {@link DEFAULT_LOG_OBJECTS}, so an unrelated `stream.write` is untouched.
 */
export const DEFAULT_LOG_FUNCTIONS: readonly string[] = [
  'log',
  'info',
  'warn',
  'error',
  'debug',
  'trace',
  'fatal',
  'verbose',
  'silly',
  'write',
];

/** Names a logger is reached by, anywhere along the callee chain. */
export const DEFAULT_LOG_OBJECTS: readonly string[] = [
  'console',
  'logger',
  'log',
  'winston',
  'pino',
  'bunyan',
  'stdout',
  'stderr',
];

/**
 * Whether a call reaches a logger.
 *
 * Two shapes count. A method call needs its method name in `logFunctions` and
 * some name along its callee chain in `logObjects`, which covers `console.log`,
 * `this.logger.info`, `req.log.warn` and `logger.child({ id }).info` alike. A
 * bare call counts when the function's own name is in `logObjects`, which is
 * how `log(...)` from a destructured import is caught.
 *
 * Matching anywhere in the chain rather than at its head is a deliberate trade:
 * it takes an object named one of eight logger names carrying a method named
 * one of ten logger methods to produce a false positive, and it is the only way
 * to see a logger that arrives as a property.
 */
export function isLogCall(
  node: AstNode,
  logFunctions: ReadonlySet<string>,
  logObjects: ReadonlySet<string>
): boolean {
  const callee = calleeOf(node);
  if (callee === undefined) {
    return false;
  }

  const bareName = identifierName(callee);
  if (bareName !== undefined) {
    return logObjects.has(bareName);
  }

  if (callee.type !== 'MemberExpression') {
    return false;
  }

  const names = calleeChainNames(callee);
  const method = names[0];
  if (method === undefined || !logFunctions.has(method)) {
    return false;
  }

  return names.slice(1).some((name) => logObjects.has(name));
}
