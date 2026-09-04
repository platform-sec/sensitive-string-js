import got from 'got';
import type { Got } from 'got';
import { startRecordingServer } from '@platform-sec/sensitive-string-http/testing';
import type { RecordingServer } from '@platform-sec/sensitive-string-http/testing';
import { SensitiveString } from '@platform-sec/sensitive-string-core';

export const CANARY = 'LEAKED_SECRET_abc123xyz';

export function token(): SensitiveString<'credential'> {
  return new SensitiveString(CANARY, 'credential', 'api_token');
}

export function instance(server: RecordingServer): Got {
  return got.extend({ prefixUrl: server.origin, retry: { limit: 0 } });
}

export { startRecordingServer };
export type { RecordingServer };
