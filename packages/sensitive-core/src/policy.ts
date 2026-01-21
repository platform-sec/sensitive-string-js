import { SensitivityClass, SensitivityPolicy, SENSITIVITY_PRECEDENCE } from './types.js';

/**
 * Internal registry of sensitivity policies.
 * Keyed by SensitivityClass name.
 */
const policyRegistry = new Map<SensitivityClass, SensitivityPolicy>();

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
    advisory: {
      allowPersistPlain: false,
      allowPersistEncrypted: true,
      allowSendToLog: true,
      criticality: 'medium',
    },
  },
  {
    name: 'credential',
    redact: createDefaultRedact('credential'),
    requireConstantTimeEquals: true,
    advisory: {
      allowPersistPlain: false,
      allowSendToLog: true,
      allowHash: true, // credentials can typically be hashed for comparison
      criticality: 'high',
    },
  },
];

// Initialize registry with default policies
for (const policy of DEFAULT_POLICIES) {
  policyRegistry.set(policy.name, policy);
}

/**
 * Options for registering a policy.
 */
export interface RegisterPolicyOptions {
  /** Allow overwriting an existing policy */
  overwrite?: boolean;
}

/**
 * Register a custom sensitivity policy.
 *
 * @throws Error if policy already exists and overwrite is not set
 */
export function registerPolicy(policy: SensitivityPolicy, opts: RegisterPolicyOptions = {}): void {
  if (policyRegistry.has(policy.name) && !opts.overwrite) {
    throw new Error(
      `Policy '${policy.name}' already registered. Use { overwrite: true } to replace.`
    );
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
