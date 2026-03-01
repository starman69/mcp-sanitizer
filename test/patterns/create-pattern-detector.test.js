/**
 * Tests for createPatternDetector factory function
 *
 * Covers the detect() and isSecure() methods on the returned detector object.
 */

const { createPatternDetector } = require('../../src/patterns');

describe('createPatternDetector', () => {
  describe('detect()', () => {
    it('should detect command injection in malicious input', () => {
      const detector = createPatternDetector();
      const result = detector.detect('rm -rf /');
      expect(result.detected).toBe(true);
      expect(result.patterns.length).toBeGreaterThan(0);
    });

    it('should not detect patterns in safe input', () => {
      const detector = createPatternDetector();
      const result = detector.detect('hello world');
      expect(result.detected).toBe(false);
      expect(result.patterns).toEqual([]);
    });

    it('should respect disabled detectors', () => {
      const detector = createPatternDetector({
        enableCommandInjection: false,
        enableSQLInjection: false,
        enablePrototypePollution: false,
        enableTemplateInjection: false,
        enableNoSQLInjection: false
      });
      const result = detector.detect('rm -rf / ; DROP TABLE users');
      expect(result.detected).toBe(false);
    });

    it('should only run enabled detectors', () => {
      const detector = createPatternDetector({
        enableCommandInjection: false,
        enableSQLInjection: true,
        enablePrototypePollution: false,
        enableTemplateInjection: false,
        enableNoSQLInjection: false
      });
      const result = detector.detect('UNION SELECT * FROM users');
      expect(result.detected).toBe(true);
      expect(result.detectionResults.sqlInjection).toBeDefined();
      expect(result.detectionResults.commandInjection).toBeUndefined();
    });
  });

  describe('isSecure()', () => {
    it('should return true for safe input', () => {
      const detector = createPatternDetector();
      expect(detector.isSecure('hello world')).toBe(true);
    });

    it('should return false for malicious input', () => {
      const detector = createPatternDetector();
      expect(detector.isSecure('rm -rf /')).toBe(false);
    });

    it('should return false for SQL injection input', () => {
      const detector = createPatternDetector();
      expect(detector.isSecure("' OR 1=1 --")).toBe(false);
    });

    it('should respect detector configuration', () => {
      const detector = createPatternDetector({
        enableCommandInjection: false,
        enableSQLInjection: false,
        enablePrototypePollution: false,
        enableTemplateInjection: false,
        enableNoSQLInjection: false
      });
      // With all detectors disabled, everything should be "secure"
      expect(detector.isSecure('rm -rf /')).toBe(true);
    });

    it('should be consistent with detect()', () => {
      const detector = createPatternDetector();
      const inputs = [
        'safe string',
        'rm -rf /',
        'SELECT * FROM users',
        '{"$where": "this.isAdmin"}',
        '__proto__',
        '{{7*7}}'
      ];

      for (const input of inputs) {
        const detectResult = detector.detect(input);
        const isSecureResult = detector.isSecure(input);
        expect(isSecureResult).toBe(!detectResult.detected);
      }
    });
  });
});
