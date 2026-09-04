import ky from 'ky';
import type { KyInstance } from 'ky';
import { startRecordingServer } from '@platform-sec/sensitive-string-http/testing';
import type { RecordingServer } from '@platform-sec/sensitive-string-http/testing';
import { SensitiveString } from '@platform-sec/sensitive-string-core';

export const CANARY = 'LEAKED_SECRET_abc123xyz';

export function token(): SensitiveString<'credential'> {
  return new SensitiveString(CANARY, 'credential', 'api_token');
}

export function instance(): KyInstance {
  return ky.create({ retry: 0 });
}

export { startRecordingServer };
export type { RecordingServer };
