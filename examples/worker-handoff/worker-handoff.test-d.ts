import { expectTypeOf } from 'vitest';
import {
  SensitiveString,
  fromWorkerPayload,
  toWorkerPayload,
  withWorkerPayload,
} from '@platform-sec/sensitive-string-core';
import type {
  RevealDetails,
  WorkerHandoffAuditDetails,
  WorkerPayload,
} from '@platform-sec/sensitive-string-core';

/**
 * The type claims the handoff makes, checked by `pnpm typecheck` and collected
 * by nothing else. Each is a claim the runtime cannot verify, which is exactly
 * why it is pinned here.
 */

declare const token: SensitiveString<'credential'>;
declare const workerData: unknown;

// The payload's values are keyed as the input was.
expectTypeOf(toWorkerPayload({ token })).toEqualTypeOf<
  WorkerPayload<{ token: SensitiveString<'credential'> }>
>();

// A non-instance value is rejected at compile time, not discovered in a worker.
// @ts-expect-error a raw string is not a SensitiveString
toWorkerPayload({ token: 'raw' });
// @ts-expect-error a wire object is not an instance either
toWorkerPayload({ token: token.serialize() });

// An interface, which is how a caller writes the shape, satisfies the constraint.
interface Claimed {
  readonly token: SensitiveString<'credential'>;
}
expectTypeOf(toWorkerPayload<Claimed>({ token })).toEqualTypeOf<WorkerPayload<Claimed>>();

// The receiving side narrows to the claimed shape, so the reveal type-checks.
const received = fromWorkerPayload<{ token: SensitiveString<'credential'> }>(workerData);
expectTypeOf(received.values.token).toEqualTypeOf<SensitiveString<'credential'>>();
expectTypeOf(received.values.token.reveal()).toBeString();
expectTypeOf(received.data).toBeUnknown();

// The wrapper infers the return type of fn, promises included.
expectTypeOf(withWorkerPayload(workerData, {}, () => 42)).toBeNumber();
expectTypeOf(withWorkerPayload(workerData, {}, () => Promise.resolve('done'))).toEqualTypeOf<
  Promise<string>
>();

// All three call forms compile, which is the thing that was broken. TypeScript
// has no partial type argument inference, so naming the values type alone was
// a hard error, "Expected 2 type arguments, but got 1", on the exact shape the
// README and the design document both showed. It now compiles, with the return
// type filled from its default rather than inferred.
expectTypeOf(
  withWorkerPayload<Claimed>(workerData, {}, ({ token }) => token.reveal())
).toBeUnknown();

// Annotating the callback's parameter infers both, which is the form to reach
// for when the result is used.
expectTypeOf(
  withWorkerPayload(workerData, {}, ({ token }: Claimed) => token.reveal())
).toBeString();

// Naming both is the other way, and the one a long callback wants.
expectTypeOf(
  withWorkerPayload<Claimed, string>(workerData, {}, ({ token }) => token.reveal())
).toBeString();

// The audit variant narrows off `operation`, beside the existing ones.
function describe(details: RevealDetails): string {
  switch (details.operation) {
    case 'worker-handoff':
      expectTypeOf(details).toEqualTypeOf<WorkerHandoffAuditDetails>();
      return `${details.key} -> ${details.worker ?? 'unnamed'}`;
    case 'reveal':
    case 'mask':
    case 'hash':
    case 'hmac':
    case 'renew':
    case 'revoke':
    case 'clear':
      return details.operation;
  }
}
void describe;
