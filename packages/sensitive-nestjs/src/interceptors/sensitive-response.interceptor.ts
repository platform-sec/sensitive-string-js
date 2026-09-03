import {
  Injectable,
  StreamableFile,
  type CallHandler,
  type ExecutionContext,
  type NestInterceptor,
} from '@nestjs/common';
import { redactCopy } from '@platform-sec/sensitive-string-core';
import { map, type Observable } from 'rxjs';

/**
 * Replace every `SensitiveString` and every serialized sensitive value in a
 * response body with its redacted form.
 *
 * This is defense in depth, not the primary guarantee: `toJSON()` already
 * redacts whenever the body reaches `JSON.stringify`. It earns its place in
 * two cases. The first is something serializing the body another way, most
 * often `ClassSerializerInterceptor`, whose `instanceToPlain` copies the public
 * `klass` and `label` of a `SensitiveString` and drops the redaction marker
 * entirely. The second is a `serialize()` result in the body: its raw `value`
 * is meant for service-to-service transport, and `JSON.stringify` emits it
 * faithfully.
 *
 * Register it after any serializer. Interceptors process responses innermost
 * first and later registration is inner, so this ordering redacts before
 * `instanceToPlain` runs:
 *
 * ```ts
 * { provide: APP_INTERCEPTOR, useClass: ClassSerializerInterceptor },
 * { provide: APP_INTERCEPTOR, useClass: SensitiveResponseInterceptor },
 * ```
 *
 * The walk is core's `redactCopy`: it never mutates the body, keeps each
 * object's prototype so entity `toJSON()` methods still run, preserves shared
 * references, and passes streams, `Buffer`, `Date`, `Map`, `Set`, `RegExp`,
 * and `URL` through. A `StreamableFile` is NestJS's own response type, which
 * core does not know, so it is passed through before the walk.
 */
@Injectable()
export class SensitiveResponseInterceptor implements NestInterceptor {
  intercept(_context: ExecutionContext, next: CallHandler): Observable<unknown> {
    return next
      .handle()
      .pipe(map((body: unknown) => (body instanceof StreamableFile ? body : redactCopy(body))));
  }
}
