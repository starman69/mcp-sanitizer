/**
 * Coverage tests for patterns/index.js
 *
 * Targets uncovered lines: 133 (hasSecurityPatterns), 158/162/166/170
 * (analyzeSecurityPatterns recommendations), 182/186-188 (getRiskLevel cases).
 */

const {
  detectAllPatterns,
  hasSecurityPatterns,
  analyzeSecurityPatterns,
  getHigherSeverity,
  getRiskLevel,
  SEVERITY_LEVELS
} = require('../../src/patterns');

describe('patterns/index.js coverage', () => {
  describe('hasSecurityPatterns', () => {
    it('should return true for command injection', () => {
      expect(hasSecurityPatterns('rm -rf /')).toBe(true);
    });

    it('should return false for safe input', () => {
      expect(hasSecurityPatterns('hello')).toBe(false);
    });
  });

  describe('analyzeSecurityPatterns', () => {
    it('should provide command injection recommendation', () => {
      const analysis = analyzeSecurityPatterns('rm -rf /');
      expect(analysis.detected).toBe(true);
      expect(analysis.recommendations).toContain(
        'Input contains command injection patterns. Sanitize shell metacharacters and validate against allowed commands.'
      );
      expect(analysis.riskLevel).toBeDefined();
    });

    it('should provide SQL injection recommendation', () => {
      const analysis = analyzeSecurityPatterns("' OR 1=1 --");
      expect(analysis.recommendations).toContain(
        'Input contains SQL injection patterns. Use parameterized queries and validate SQL keywords.'
      );
    });

    it('should provide prototype pollution recommendation', () => {
      const analysis = analyzeSecurityPatterns('__proto__');
      expect(analysis.recommendations).toContain(
        'Input contains prototype pollution patterns. Validate object keys and use Object.create(null) for safe objects.'
      );
    });

    it('should provide template injection recommendation', () => {
      const analysis = analyzeSecurityPatterns('{{7*7}}');
      expect(analysis.recommendations).toContain(
        'Input contains template injection patterns. Sanitize template syntax and use safe template engines.'
      );
    });

    it('should provide NoSQL injection recommendation', () => {
      const analysis = analyzeSecurityPatterns('{"$where": "this.isAdmin"}');
      expect(analysis.recommendations).toContain(
        'Input contains NoSQL injection patterns. Validate database operators, sanitize user input, and use parameterized queries.'
      );
    });

    it('should set shouldBlock for critical severity', () => {
      const analysis = analyzeSecurityPatterns('rm -rf /');
      expect(analysis.shouldBlock).toBe(true);
    });

    it('should not set shouldBlock for non-critical', () => {
      const analysis = analyzeSecurityPatterns('hello');
      expect(analysis.shouldBlock).toBe(false);
    });

    it('should have empty recommendations for safe input', () => {
      const analysis = analyzeSecurityPatterns('safe input');
      expect(analysis.recommendations).toEqual([]);
      expect(analysis.riskLevel).toBe('NONE');
    });
  });

  describe('getRiskLevel', () => {
    it('should return CRITICAL for critical severity', () => {
      expect(getRiskLevel(SEVERITY_LEVELS.CRITICAL)).toBe('CRITICAL');
    });

    it('should return HIGH for high severity', () => {
      expect(getRiskLevel(SEVERITY_LEVELS.HIGH)).toBe('HIGH');
    });

    it('should return MEDIUM for medium severity', () => {
      expect(getRiskLevel(SEVERITY_LEVELS.MEDIUM)).toBe('MEDIUM');
    });

    it('should return LOW for low severity', () => {
      expect(getRiskLevel(SEVERITY_LEVELS.LOW)).toBe('LOW');
    });

    it('should return NONE for null/undefined severity', () => {
      expect(getRiskLevel(null)).toBe('NONE');
      expect(getRiskLevel(undefined)).toBe('NONE');
    });
  });

  describe('getHigherSeverity', () => {
    it('should return newSeverity when current is null', () => {
      expect(getHigherSeverity(null, 'high')).toBe('high');
    });

    it('should return current when newSeverity is null', () => {
      expect(getHigherSeverity('high', null)).toBe('high');
    });

    it('should return critical over high', () => {
      expect(getHigherSeverity('high', 'critical')).toBe('critical');
    });

    it('should keep critical when new is lower', () => {
      expect(getHigherSeverity('critical', 'low')).toBe('critical');
    });
  });

  describe('detectAllPatterns summary', () => {
    it('should count patterns by type and severity', () => {
      const result = detectAllPatterns('rm -rf / UNION SELECT * FROM users');
      expect(result.detected).toBe(true);
      expect(result.summary.totalPatterns).toBeGreaterThan(0);
      expect(result.summary.patternsByType).toBeDefined();
      expect(result.summary.patternsBySeverity).toBeDefined();
      expect(result.message).toContain('security patterns detected');
    });

    it('should report zero patterns for safe input', () => {
      const result = detectAllPatterns('safe');
      expect(result.detected).toBe(false);
      expect(result.summary.totalPatterns).toBe(0);
    });
  });
});
