import axios from 'axios';
import type { AxiosInstance } from 'axios';
import { startRecordingServer } from '@platform-sec/sensitive-string-http/testing';
import type { RecordingServer } from '@platform-sec/sensitive-string-http/testing';
import { SensitiveString } from '@platform-sec/sensitive-string-core';

/** Conspicuous, so a leak assertion is unambiguous about what it found. */
export const CANARY = 'LEAKED_SECRET_abc123xyz';

export function token(): SensitiveString<'credential'> {
  return new SensitiveString(CANARY, 'credential', 'api_token');
}

export function instance(server: RecordingServer): AxiosInstance {
  return axios.create({ baseURL: server.origin });
}

export { startRecordingServer };
export type { RecordingServer };
