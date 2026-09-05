import { SensitivityClass, SensitivityPolicy, SENSITIVITY_PRECEDENCE } from './types.js';
import { getGlobalSingleton } from './global-state.js';

/**
 * Determine the more restrictive class when combining two sensitive values.
 * Uses SENSITIVITY_PRECEDENCE ordering (higher index = more restrictive).
 */
export function defaultCombineClasses(a: SensitivityClass, b: SensitivityClass): SensitivityClass {
  const indexA = SENSITIVITY_PRECEDENCE.indexOf(a);
  const indexB = SENSITIVITY_PRECEDENCE.indexOf(b);
  return indexA >= indexB ? a : b;
}

/**
 * Create a default redaction string for a sensitivity class.
 */
function createDefaultRedact(klass: SensitivityClass): (value: string) => string {
  return (_value: string) => `[REDACTED:${klass}]`;
}

/**
 * Default policies.
 * Two classes based on the only behavioral difference that matters:
 * - credential: constant-time comparison (for timing attack prevention)
 * - sensitive: regular comparison (for everything else)
 */
const DEFAULT_POLICIES: SensitivityPolicy[] = [
  {
    name: 'sensitive',
    redact: createDefaultRedact('sensitive'),
    requireConstantTimeEquals: false,
    allowPartialQueries: true,
    allowMask: true,
    advisory: {
      allowPersistPlain: false,
      allowPersistEncrypted: true,
      allowSendToLog: true,
      // Written explicitly, though `undefined` is a refusal wherever this flag
      // is read. Absent and `false` behave identically and read completely
      // differently to somebody reviewing a policy: absent looks like an
      // oversight. `sensitive` starts closed because the class is deliberately
      // coarse and covers a customer email as readily as an internal note. A
      // caller who wants either in a prompt registers a policy saying so, in
      // one place, in code that shows up in review.
      allowSendToExternal: false,
      criticality: 'medium',
    },
  },
  {
    name: 'credential',
    redact: createDefaultRedact('credential'),
    requireConstantTimeEquals: true,
    allowPartialQueries: false,
    allowMask: false,
    advisory: {
      allowPersistPlain: false,
      allowSendToLog: true,
      allowHash: true, // credentials can typically be hashed for comparison
      // See the note on `sensitive` above. A credential bound for a third
      // party is the case this flag exists for.
      allowSendToExternal: false,
      criticality: 'high',
    },
  },
];

/**
 * Internal registry of sensitivity policies.
 *
 * The Symbol.for()-backed singleton keeps policy changes visible when an
 * application loads multiple physical copies of core.
 */
const policyRegistry = getGlobalSingleton(
  'policy-registry',
  () => new Map(DEFAULT_POLICIES.map((policy) => [policy.name, policy]))
);

/**
 * Options for registering a policy.
 */
export interface RegisterPolicyOptions {
  /** Allow overwriting an existing policy */
  overwrite?: boolean;
  /**
   * Skip validation of the redact function.
   * ⚠️ DANGEROUS - only use for testing malicious policy behavior.
   */
  skipRedactValidation?: boolean;
}

/**
 * Validate that a redact function actually redacts the value.
 * Tests with multiple canary values to catch identity functions and partial leaks.
 *
 * @throws Error if the redact function returns or contains the original value
 */
function validateRedactFunction(redact: (value: string) => string): void {
  // Test with multiple canary values to catch various bypass attempts
  const canaries = [
    'VALIDATION_CANARY_' + Math.random().toString(36).slice(2),
    'test-secret-value-12345',
    '<script>alert(1)</script>', // XSS-like payload
  ];

  for (const canary of canaries) {
    const result = redact(canary);

    // Check for identity function
    if (result === canary) {
      throw new Error('Invalid redact function: must not return the original value unchanged');
    }

    // Check for partial inclusion (value embedded in output)
    // Only check if canary is long enough to be meaningful
    if (canary.length >= 8 && result.includes(canary)) {
      throw new Error('Invalid redact function: must not include the original value in output');
    }
  }
}

/**
 * Register a custom sensitivity policy.
 *
 * @throws Error if policy already exists and overwrite is not set
 * @throws Error if redact function does not actually redact values
 */
export function registerPolicy(policy: SensitivityPolicy, opts: RegisterPolicyOptions = {}): void {
  if (policyRegistry.has(policy.name) && !opts.overwrite) {
    throw new Error(
      `Policy '${policy.name}' already registered. Use { overwrite: true } to replace.`
    );
  }

  // Validate the redact function unless explicitly skipped
  if (!opts.skipRedactValidation) {
    validateRedactFunction((value) => policy.redact(value));
  }

  policyRegistry.set(policy.name, policy);
}

/**
 * Get the policy for a sensitivity class.
 *
 * @throws Error if no policy is registered for the class
 */
export function getPolicy(name: SensitivityClass): SensitivityPolicy {
  const policy = policyRegistry.get(name);
  if (!policy) {
    throw new Error(`No policy registered for sensitivity class '${name}'`);
  }
  return policy;
}

/**
 * Get the default policy (for 'sensitive' class).
 */
export function getDefaultPolicy(): SensitivityPolicy {
  return getPolicy('sensitive');
}

/**
 * Check if a policy is registered for a sensitivity class.
 */
export function hasPolicy(name: SensitivityClass): boolean {
  return policyRegistry.has(name);
}

/**
 * Get all registered sensitivity classes.
 */
export function getRegisteredClasses(): SensitivityClass[] {
  return Array.from(policyRegistry.keys());
}

/**
 * Reset policies to defaults.
 * Primarily useful for testing.
 */
export function resetPolicies(): void {
  policyRegistry.clear();
  for (const policy of DEFAULT_POLICIES) {
    policyRegistry.set(policy.name, policy);
  }
}
