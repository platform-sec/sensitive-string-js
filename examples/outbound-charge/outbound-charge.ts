/**
 * Outbound Charge - revealing at the wire without leaving the value behind
 *
 * An HTTP client is the one integration where the library's default is wrong
 * for the caller's intent. Everywhere else a redaction loses information and
 * nobody is harmed; at the wire the intent is to transmit the value, so a
 * `SensitiveString` interpolated into a header sends
 * `Authorization: Bearer [REDACTED:credential]`, nothing throws, the server
 * answers 401, and the first person to debug it pastes the raw token back in.
 *
 * This example shows the shape the `fetch` integration gives that call instead:
 * the instances stay wrapped in application code, the reveal happens once
 * inside the wrapper, and the response's sensitive fields come back wrapped.
 *
 * @example
 * ```ts
 * const receipt = await chargeCard(client, { amount: 4200, currency: 'usd' });
 * receipt.customerEmail; // SensitiveString<sensitive>, not a plain string
 * ```
 */

import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { bearer, sensitiveFetch } from '@platform-sec/sensitive-string-fetch';

/** Everything the caller holds is wrapped, from the environment onward. */
export interface PaymentClient {
  readonly endpoint: string;
  readonly apiToken: SensitiveString<'credential'>;
  readonly cardNumber: SensitiveString<'credential'>;
}

export interface ChargeRequest {
  readonly amount: number;
  readonly currency: string;
}

export interface ChargeReceipt {
  readonly id: string;
  readonly customerEmail: SensitiveString<'sensitive'>;
}

/**
 * Build the client from the environment.
 *
 * `fromOptional` returns `null` for an absent or empty value, which is what
 * keeps a missing variable from becoming an empty credential that fails at the
 * gateway instead of at startup.
 */
export function paymentClientFromEnv(env: NodeJS.ProcessEnv): PaymentClient {
  const apiToken = SensitiveString.fromOptional(
    env['PAYMENT_API_TOKEN'],
    'credential',
    'api_token'
  );
  const cardNumber = SensitiveString.fromOptional(env['TEST_CARD_NUMBER'], 'credential', 'pan');

  if (apiToken === null || cardNumber === null) {
    throw new Error('PAYMENT_API_TOKEN and TEST_CARD_NUMBER must be set');
  }

  return { endpoint: env['PAYMENT_ENDPOINT'] ?? 'https://api.example.com', apiToken, cardNumber };
}

/**
 * One outbound call.
 *
 * Four things are worth reading closely:
 *
 * - `bearer(client.apiToken)` rather than `` `Bearer ${client.apiToken}` ``.
 *   The helper takes the instance, so the reveal and the encoding both happen
 *   inside the wrapper, where the marker guard can read the result. The
 *   template literal is the single most likely way for a marker to reach a
 *   header, and it is unreachable here.
 * - `sensitiveJson` rather than `body`. The wrapper reveals the structure and
 *   serializes it, so `card.number` never becomes a loose string in this frame.
 * - `allowedHosts` names where a redirect may lead, derived from the endpoint
 *   so the two cannot drift apart. Measured, axios, got and Node's `fetch` all
 *   forward a non-standard auth header such as `x-api-key` verbatim across
 *   origins; the Fetch specification only requires stripping `Authorization`,
 *   `Cookie` and `Proxy-Authorization`.
 * - `responseFields` wraps the response paths before the `await` resolves, so
 *   the customer's email is never a plain `string` anywhere in this function.
 */
export async function chargeCard(
  client: PaymentClient,
  charge: ChargeRequest
): Promise<ChargeReceipt> {
  return sensitiveFetch<ChargeReceipt>(`${client.endpoint}/charges`, {
    method: 'POST',
    reason: 'charge authorization',
    headers: { authorization: bearer(client.apiToken) },
    sensitiveJson: {
      amount: charge.amount,
      currency: charge.currency,
      card: { number: client.cardNumber },
    },
    allowedHosts: [new URL(client.endpoint).host],
    responseFields: { customerEmail: 'sensitive' },
  }).json();
}

/**
 * What a log line looks like from here.
 *
 * The receipt holds a wrapped email, so an ordinary `console.log` of it is
 * already safe, and no `safeLog` call is needed to make it so.
 */
export function describeReceipt(receipt: ChargeReceipt): string {
  return `charge ${receipt.id} for ${String(receipt.customerEmail)}`;
}
