# Worker handoff

A signing key moved into a worker thread as a `SensitiveString`, revealed once inside it under the
context it was sent with, and gone from the payload object by the time the worker's own code runs.

## What this shows

| Line | What it prevents |
|---|---|
| `toWorkerPayload({ signingKey })` | `workerData: { signingKey }` delivering a `{ klass, label }` that fails at the first method call, in the worker |
| `worker: SIGNER_FILE` | an audit record that says a credential was revealed and not where it went |
| `data: batch` | the documents riding in `values`, where a non-instance is refused, or a `SensitiveString` riding in `data`, where it would degrade in silence |
| `auditReveal` in the worker | reveals in the thread going unrecorded after the sender asked for them to be recorded; the sender's hook cannot cross |
| `require: ['signingKey']` | a missing key surfacing as a `TypeError` in the signing loop rather than at the boundary |
| `withWorkerPayload` | destructuring `values` and forgetting `context`, which reads as handled and audits nothing |

## The part that is not visible in the code

`workerData` is one mutable object shared by every module in the thread. `withWorkerPayload()`
deletes the raw values from it and marks it consumed, so a `console.log(workerData)` in a dependency,
or a crash handler serializing it, no longer reads the key. That closes the accident window, which
otherwise runs for the life of the thread. It does not close the memory window: a heap snapshot still
holds the string until it is collected, which is the library's standing limitation everywhere.

Two more things the handoff does not change, both worth knowing before trusting the boundary:
`process.env` is copied into every worker unless the `Worker` constructor is given an `env`
allowlist, and an application error thrown in the worker carries its `message` and `stack` to the
parent's `'error'` handler as they are.

## Running it

The main-thread half runs wherever a `Worker` is constructed; the worker half runs at the top of
the worker's entry file:

```ts
// signer.js
import { parentPort, workerData } from 'node:worker_threads';
import { signBatch } from './worker-handoff.js';

parentPort.postMessage(
  signBatch(workerData, (value, details) => log.info('reveal', { klass: value.klass, ...details }))
);
```

The suite beside it runs both halves in one process with `structuredClone` standing in for the
boundary. Core's own suite drives the same helpers through a real `Worker`, a forked child, a
`MessageChannel` and a `BroadcastChannel`.
