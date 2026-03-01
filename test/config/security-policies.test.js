/**
 * Coverage tests for config/security-policies.js
 *
 * Targets: getSecurityPolicy (deep clone with RegExp), createCustomPolicy
 * (deep merge with RegExp/arrays/objects), getPolicyRecommendation (all
 * environment/trust combos, error paths), validatePolicyRequirements
 * (all violation/warning branches).
 */

const {
  getSecurityPolicy,
  createCustomPolicy,
  getPolicyRecommendation,
  validatePolicyRequirements,
  SECURITY_POLICIES,
  POLICY_NAMES,
  STRICT_POLICY,
  MODERATE_POLICY,
  PERMISSIVE_POLICY
} = require('../../src/config/security-policies');

describe('security-policies', () => {
  describe('getSecurityPolicy', () => {
    it('should return STRICT policy', () => {
      const policy = getSecurityPolicy('STRICT');
      expect(policy.strictMode).toBe(true);
      expect(policy.allowedProtocols).toEqual(['https']);
    });

    it('should return MODERATE policy', () => {
      const policy = getSecurityPolicy('MODERATE');
      expect(policy.allowedProtocols).toContain('http');
    });

    it('should return PERMISSIVE policy', () => {
      const policy = getSecurityPolicy('PERMISSIVE');
      expect(policy.maxStringLength).toBe(50000);
    });

    it('should return DEVELOPMENT policy', () => {
      const policy = getSecurityPolicy('DEVELOPMENT');
      expect(policy.allowedProtocols).toContain('file');
    });

    it('should return PRODUCTION policy', () => {
      const policy = getSecurityPolicy('PRODUCTION');
      expect(policy.strictMode).toBe(true);
    });

    it('should be case-insensitive', () => {
      const policy = getSecurityPolicy('strict');
      expect(policy.strictMode).toBe(true);
    });

    it('should deep clone the policy (not return the same reference)', () => {
      const p1 = getSecurityPolicy('STRICT');
      const p2 = getSecurityPolicy('STRICT');
      expect(p1).not.toBe(p2);
      expect(p1).toEqual(p2);
    });

    it('should clone RegExp objects in blockedPatterns', () => {
      const policy = getSecurityPolicy('STRICT');
      expect(policy.blockedPatterns[0]).toBeInstanceOf(RegExp);
      expect(policy.blockedPatterns[0]).not.toBe(STRICT_POLICY.blockedPatterns[0]);
    });

    it('should throw for non-string policy name', () => {
      expect(() => getSecurityPolicy(123)).toThrow('Policy name must be a string');
    });

    it('should throw for invalid policy name', () => {
      expect(() => getSecurityPolicy('INVALID')).toThrow('Invalid security policy');
    });
  });

  describe('createCustomPolicy', () => {
    it('should extend a base policy with primitive overrides', () => {
      const custom = createCustomPolicy('MODERATE', { maxStringLength: 10000 });
      expect(custom.maxStringLength).toBe(10000);
      expect(custom.allowedProtocols).toEqual(MODERATE_POLICY.allowedProtocols);
    });

    it('should deep merge nested objects', () => {
      const custom = createCustomPolicy('MODERATE', {
        contextSettings: {
          url: { maxURLLength: 4096 }
        }
      });
      expect(custom.contextSettings.url.maxURLLength).toBe(4096);
      // Other url properties preserved
      expect(custom.contextSettings.url.allowPrivateIPs).toBe(false);
    });

    it('should replace arrays with source arrays', () => {
      const custom = createCustomPolicy('STRICT', {
        allowedProtocols: ['http', 'https', 'ftp']
      });
      expect(custom.allowedProtocols).toEqual(['http', 'https', 'ftp']);
    });

    it('should clone RegExp objects in arrays', () => {
      const customPattern = /custom-pattern/gi;
      const custom = createCustomPolicy('PERMISSIVE', {
        blockedPatterns: [customPattern]
      });
      expect(custom.blockedPatterns[0].source).toBe('custom-pattern');
      expect(custom.blockedPatterns[0]).not.toBe(customPattern);
    });

    it('should clone standalone RegExp values', () => {
      const custom = createCustomPolicy('MODERATE', {
        customRegex: /test-regex/i
      });
      expect(custom.customRegex).toBeInstanceOf(RegExp);
      expect(custom.customRegex.source).toBe('test-regex');
    });
  });

  describe('getPolicyRecommendation', () => {
    it('should recommend PERMISSIVE for dev/high trust', () => {
      const rec = getPolicyRecommendation('development', 'high');
      expect(rec.recommended).toBe('PERMISSIVE');
      expect(rec.policy).toBeDefined();
      expect(rec.rationale).toContain('development');
    });

    it('should recommend DEVELOPMENT for dev/medium trust', () => {
      const rec = getPolicyRecommendation('development', 'medium');
      expect(rec.recommended).toBe('DEVELOPMENT');
    });

    it('should recommend MODERATE for dev/low trust', () => {
      const rec = getPolicyRecommendation('development', 'low');
      expect(rec.recommended).toBe('MODERATE');
    });

    it('should recommend MODERATE for staging/high trust', () => {
      const rec = getPolicyRecommendation('staging', 'high');
      expect(rec.recommended).toBe('MODERATE');
    });

    it('should recommend PRODUCTION for staging/low trust', () => {
      const rec = getPolicyRecommendation('staging', 'low');
      expect(rec.recommended).toBe('PRODUCTION');
    });

    it('should recommend MODERATE for production/high trust', () => {
      const rec = getPolicyRecommendation('production', 'high');
      expect(rec.recommended).toBe('MODERATE');
    });

    it('should recommend PRODUCTION for production/medium trust', () => {
      const rec = getPolicyRecommendation('production', 'medium');
      expect(rec.recommended).toBe('PRODUCTION');
    });

    it('should recommend STRICT for production/low trust', () => {
      const rec = getPolicyRecommendation('production', 'low');
      expect(rec.recommended).toBe('STRICT');
    });

    it('should throw for invalid environment', () => {
      expect(() => getPolicyRecommendation('invalid', 'low')).toThrow('Invalid environment');
    });

    it('should throw for invalid trust level', () => {
      expect(() => getPolicyRecommendation('production', 'invalid')).toThrow('Invalid trust level');
    });
  });

  describe('validatePolicyRequirements', () => {
    it('should pass with no requirements', () => {
      const result = validatePolicyRequirements(STRICT_POLICY);
      expect(result.valid).toBe(true);
      expect(result.violations).toEqual([]);
    });

    it('should flag HTTP when HTTPS required', () => {
      const result = validatePolicyRequirements(MODERATE_POLICY, { requireHTTPS: true });
      expect(result.valid).toBe(false);
      expect(result.violations.some(v => v.includes('HTTP protocol'))).toBe(true);
    });

    it('should pass HTTPS check for STRICT policy', () => {
      const result = validatePolicyRequirements(STRICT_POLICY, { requireHTTPS: true });
      expect(result.valid).toBe(true);
    });

    it('should flag maxStringLength violation', () => {
      const result = validatePolicyRequirements(PERMISSIVE_POLICY, { maxStringLength: 1000 });
      expect(result.valid).toBe(false);
      expect(result.violations.some(v => v.includes('strings longer'))).toBe(true);
    });

    it('should pass maxStringLength for STRICT policy', () => {
      const result = validatePolicyRequirements(STRICT_POLICY, { maxStringLength: 5000 });
      expect(result.valid).toBe(true);
    });

    it('should flag severity blocking violation', () => {
      // PERMISSIVE blocks at 'critical', require 'medium'
      const result = validatePolicyRequirements(PERMISSIVE_POLICY, { blockSeverity: 'medium' });
      expect(result.valid).toBe(false);
      expect(result.violations.some(v => v.includes('severity'))).toBe(true);
    });

    it('should pass severity check when policy is stricter', () => {
      // STRICT blocks at 'medium', require 'high'
      const result = validatePolicyRequirements(STRICT_POLICY, { blockSeverity: 'high' });
      expect(result.valid).toBe(true);
    });

    it('should warn about disabled pattern detection', () => {
      const result = validatePolicyRequirements(PERMISSIVE_POLICY, {
        requireAllPatternDetection: true
      });
      expect(result.warnings.length).toBeGreaterThan(0);
      expect(result.warnings.some(w => w.includes('disabled'))).toBe(true);
    });

    it('should have no warnings when all detection enabled', () => {
      const result = validatePolicyRequirements(STRICT_POLICY, {
        requireAllPatternDetection: true
      });
      expect(result.warnings).toEqual([]);
    });
  });

  describe('constants', () => {
    it('should export all policy names', () => {
      expect(POLICY_NAMES).toEqual(expect.arrayContaining([
        'STRICT', 'MODERATE', 'PERMISSIVE', 'DEVELOPMENT', 'PRODUCTION'
      ]));
    });

    it('should export SECURITY_POLICIES object', () => {
      expect(Object.keys(SECURITY_POLICIES)).toEqual(POLICY_NAMES);
    });
  });
});
