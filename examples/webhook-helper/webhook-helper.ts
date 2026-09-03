/**
 * Webhook Helper - Atomic Parse and Protect Pattern
 *
 * This module demonstrates how to safely handle webhook payloads from
 * payment service providers by combining parsing and sensitive field
 * protection into a single atomic operation.
 *
 * @example
 * ```typescript
 * import { parseAndProtectWebhook, PSP_SENSITIVE_FIELDS } from './webhook-helper';
 *
 * app.post('/webhooks/payment', (req, res) => {
 *   const notification = parseAndProtectWebhook(
 *     req.body,
 *     JSON.parse,
 *     PSP_SENSITIVE_FIELDS
 *   );
 *   // Safe to log - SensitiveStrings auto-redact via toJSON()
 *   logger.info('Webhook received', notification);
 * });
 * ```
 */

import { wrapSensitiveByPath, unwrapSensitiveByPath } from '@platform-sec/sensitive-string-core';
import type {
  SensitiveFieldConfig,
  RevealContext,
  SensitiveString,
} from '@platform-sec/sensitive-string-core';

// ============================================================
// Generic Helper Functions
// ============================================================

/**
 * Atomically parse and protect a webhook payload.
 *
 * This helper ensures there's no window where raw sensitive data
 * exists in an unprotected form. The parsing and wrapping happen
 * in immediate succession with no opportunity for logging or
 * other operations to access the raw data.
 *
 * @param rawBody - The raw string body from the HTTP request
 * @param parser - Function to parse the raw body (e.g., JSON.parse or SDK method)
 * @param sensitiveFields - Configuration mapping paths to sensitivity classes
 * @returns The parsed object with sensitive fields wrapped as SensitiveString
 *
 * @example
 * ```typescript
 * const notification = parseAndProtectWebhook(
 *   req.body,
 *   (body) => paymentSdk.parseWebhook(body),
 *   PSP_SENSITIVE_FIELDS
 * );
 * ```
 */
export function parseAndProtectWebhook<T extends object>(
  rawBody: string,
  parser: (body: string) => T,
  sensitiveFields: SensitiveFieldConfig
): T {
  // Parse and wrap atomically - no gap for leakage
  return wrapSensitiveByPath(parser(rawBody), sensitiveFields);
}

/**
 * Unwrap a protected webhook payload back to raw strings.
 *
 * Use this when you need to forward the webhook to another service
 * that doesn't understand SensitiveString, or when serializing
 * for storage in a secure backend.
 *
 * @param protectedPayload - The webhook with SensitiveString fields
 * @param sensitiveFields - Same configuration used for wrapping
 * @param ctx - Optional reveal context for auditing
 * @returns The payload with sensitive fields as plain strings
 */
export function unprotectWebhook<T extends object>(
  protectedPayload: T,
  sensitiveFields: SensitiveFieldConfig,
  ctx?: RevealContext
): T {
  return unwrapSensitiveByPath(protectedPayload, sensitiveFields, ctx);
}

/**
 * Create a provider-specific webhook handler.
 *
 * This factory creates a specialized parseAndProtect function
 * with the parser and config pre-configured for a specific provider.
 *
 * @param parser - Provider-specific parsing function
 * @param sensitiveFields - Provider-specific sensitivity configuration
 * @returns A function that takes raw body and returns protected payload
 *
 * @example
 * ```typescript
 * const parseStripeWebhook = createWebhookHandler(
 *   (body) => stripe.webhooks.constructEvent(body, sig, secret),
 *   STRIPE_SENSITIVE_FIELDS
 * );
 *
 * app.post('/webhooks/stripe', (req, res) => {
 *   const event = parseStripeWebhook(req.body);
 * });
 * ```
 */
export function createWebhookHandler<T extends object>(
  parser: (body: string) => T,
  sensitiveFields: SensitiveFieldConfig
): (rawBody: string) => T {
  return (rawBody: string) => parseAndProtectWebhook(rawBody, parser, sensitiveFields);
}

// ============================================================
// Example: Payment Service Provider Configuration
// ============================================================

/**
 * Typed shape for the sample payment webhook payload.
 * Sensitive fields are represented as string | SensitiveString
 * so the type works before and after wrapping.
 */
export type PspWebhookPayload = {
  notification: {
    metadata: {
      webhookSignature: string | SensitiveString<'credential'>;
      cardLastFour: string | SensitiveString<'sensitive'>;
      cardBinPrefix: string | SensitiveString<'sensitive'>;
      cardExpiry: string | SensitiveString<'sensitive'>;
      cardholderName: string | SensitiveString<'sensitive'>;
      customerIpAddress: string | SensitiveString<'sensitive'>;
      customerEmail: string | SensitiveString<'sensitive'>;
      paymentTokenAlias: string | SensitiveString<'credential'>;
      networkReference: string | SensitiveString<'credential'>;
      riskScore: string;
      fraudCheckPassed: string;
    };
    transaction: {
      gatewayReference: string | SensitiveString<'credential'>;
      authorizationDetails: string | SensitiveString<'sensitive'>;
      status: string;
      amount: {
        currency: string;
        value: number;
      };
      merchantId: string;
    };
  };
};

/**
 * Typed JSON.parse helper for the sample PSP payload.
 */
export const parsePspWebhookPayload = (body: string): PspWebhookPayload =>
  JSON.parse(body) as PspWebhookPayload;

/**
 * Sample sensitive field configuration for a generic Payment Service Provider.
 *
 * This configuration identifies fields that contain:
 * - Secrets (webhook signatures, API keys)
 * - PII (card data, customer information)
 * - Tokens (payment references, aliases)
 *
 * Customize this for your specific payment provider.
 */
export const PSP_SENSITIVE_FIELDS: SensitiveFieldConfig = {
  // Secrets - used for verification, never log
  'notification.metadata.webhookSignature': 'credential',

  // PII - Card data
  'notification.metadata.cardLastFour': 'sensitive',
  'notification.metadata.cardBinPrefix': 'sensitive',
  'notification.metadata.cardExpiry': 'sensitive',
  'notification.metadata.cardholderName': 'sensitive',

  // PII - Customer data
  'notification.metadata.customerIpAddress': 'sensitive',
  'notification.metadata.customerEmail': 'sensitive',

  // Tokens - Reference IDs that could be used for lookups
  'notification.metadata.paymentTokenAlias': 'credential',
  'notification.metadata.networkReference': 'credential',
  'notification.transaction.gatewayReference': 'credential',

  // Composite fields that may contain sensitive data
  'notification.transaction.authorizationDetails': 'sensitive',
};

/**
 * Pre-configured handler for the sample PSP.
 *
 * @example
 * ```typescript
 * const notification = parsePspWebhook(req.body);
 * ```
 */
export const parsePspWebhook = createWebhookHandler<PspWebhookPayload>(
  parsePspWebhookPayload,
  PSP_SENSITIVE_FIELDS
);

// ============================================================
// Example: Multiple Provider Support
// ============================================================

/**
 * Example of how to structure configurations for multiple providers.
 * Each provider has its own sensitivity mapping based on their
 * specific payload structure.
 */
export const PROVIDER_CONFIGS = {
  /**
   * Generic PSP configuration (example)
   */
  psp: PSP_SENSITIVE_FIELDS,

  /**
   * Example structure for another payment provider.
   * Paths would match that provider's webhook structure.
   */
  alternateProvider: {
    'data.object.payment_method_details.card.last4': 'sensitive',
    'data.object.payment_method_details.card.fingerprint': 'credential',
    'data.object.billing_details.email': 'sensitive',
    'data.object.billing_details.name': 'sensitive',
    'data.object.billing_details.address.line1': 'sensitive',
    'data.object.receipt_email': 'sensitive',
  } satisfies SensitiveFieldConfig,
} as const;
