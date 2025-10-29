/**
 * Unified Parser Tests
 *
 * Comprehensive tests for unified-parser module covering:
 * - NormalizedString immutability and security
 * - parseUnified function with various inputs
 * - Batch parsing operations
 * - Validator wrapping
 * - Error handling and edge cases
 *
 * Priority: HIGH - Covers 100+ lines (21.91% coverage gap)
 */

const {
  NormalizedString,
  parseUnified,
  parseUnifiedBatch,
  isNormalizedString,
  extractNormalized,
  wrapValidator
} = require('../../src/utils/unified-parser');

describe('Unified Parser Tests', () => {
  describe('NormalizedString Immutability', () => {
    it('should create immutable NormalizedString instance', () => {
      const original = '<script>alert(1)</script>';
      const normalized = '&lt;script&gt;alert(1)&lt;/script&gt;';
      const ns = new NormalizedString(original, normalized, { test: true });

      // Properties are read-only (writable: false)
      ns._original = 'modified';
      ns._normalized = 'modified';

      // Values should remain unchanged due to writable: false
      expect(ns._original).toBe(original);
      expect(ns._normalized).toBe(normalized);

      expect(Object.isFrozen(ns)).toBe(true);
    });

    it('should provide immutable metadata', () => {
      const ns = parseUnified('test', { type: 'generic' });
      const metadata = ns.getMetadata();

      expect(metadata).toBeDefined();
      expect(Object.isFrozen(metadata)).toBe(true);

      // Cannot modify frozen metadata
      metadata.newProp = 'value';
      expect(metadata.newProp).toBeUndefined(); // Assignment fails silently on frozen object
    });

    it('should proxy string methods correctly', () => {
      const ns = parseUnified('Hello <script>World</script>');

      // Test string methods
      expect(ns.includes('Hello')).toBe(true);
      expect(ns.indexOf('Hello')).toBe(0);
      expect(ns.match(/Hello/)).toBeTruthy();

      // Test immutable operations return new NormalizedString
      const lower = ns.toLowerCase();
      expect(isNormalizedString(lower)).toBe(true);
      expect(lower.toString()).toContain('hello');

      const sliced = ns.slice(0, 5);
      expect(isNormalizedString(sliced)).toBe(true);

      const trimmed = ns.trim();
      expect(isNormalizedString(trimmed)).toBe(true);
    });

    it('should track modifications in metadata', () => {
      const ns = parseUnified('Test String');
      const lowered = ns.toLowerCase();

      const metadata = lowered.getMetadata();
      expect(metadata.wasModified).toBe(true);
      expect(metadata.lastOperation).toBe('toLowerCase');
    });

    it('should handle split operations correctly', () => {
      const ns = parseUnified('one,two,three');
      const parts = ns.split(',');

      expect(Array.isArray(parts)).toBe(true);
      expect(parts).toHaveLength(3);
      expect(isNormalizedString(parts[0])).toBe(true);
      expect(parts[0].toString()).toBe('one');
    });
  });

  describe('parseUnified Function', () => {
    it('should parse simple strings', () => {
      const result = parseUnified('simple string');

      expect(isNormalizedString(result)).toBe(true);
      expect(result.toString()).toBe('simple string');
      expect(result.length).toBe(13);
    });

    it('should handle malformed HTML edge cases', () => {
      const malformed = [
        '<script<script>alert(1)</script>',
        '<img src="x" onerror="alert(1)"',
        '<<script>>alert()<<//script>>',
        '<iframe src=javascript:alert(1)>',
        '<svg/onload=alert(1)>'
      ];

      malformed.forEach(html => {
        const result = parseUnified(html, { type: 'generic' });
        expect(isNormalizedString(result)).toBe(true);
        expect(result.toString()).toBeDefined();
        expect(result.getMetadata()).toHaveProperty('parserDifferentialPrevented', true);
      });
    });

    it('should handle deeply nested structures', () => {
      const nested = '<div>' + '<span>'.repeat(100) + 'content' + '</span>'.repeat(100) + '</div>';

      const result = parseUnified(nested, { type: 'generic' });
      expect(isNormalizedString(result)).toBe(true);
      expect(result.toString().length).toBeGreaterThan(0);
    });

    it('should handle invalid UTF-8 sequences', () => {
      const invalidUtf8 = [
        'hello\uD800world', // Lone surrogate
        'test\uDFFFstring', // Invalid surrogate
        'normal text'
      ];

      invalidUtf8.forEach(str => {
        const result = parseUnified(str, { type: 'generic' });
        expect(isNormalizedString(result)).toBe(true);
        expect(result.toString()).toBeDefined();
      });
    });

    it('should detect normalization changes', () => {
      const encoded = 'hello%20world';
      const result = parseUnified(encoded, { type: 'generic' });

      expect(isNormalizedString(result)).toBe(true);
      const metadata = result.getMetadata();
      expect(metadata).toHaveProperty('wasDecoded');
    });

    it('should handle different input types', () => {
      const typeTests = [
        { input: '../../../etc/passwd', type: 'file_path' },
        { input: 'https://example.com/test', type: 'url' },
        { input: 'rm -rf /', type: 'command' },
        { input: 'SELECT * FROM users', type: 'sql' }
      ];

      typeTests.forEach(({ input, type }) => {
        const result = parseUnified(input, { type });
        expect(isNormalizedString(result)).toBe(true);
        expect(result.getMetadata().inputType).toBe(type);
      });
    });

    it('should throw error for non-string input', () => {
      expect(() => parseUnified(123)).toThrow('parseUnified: Input must be a string');
      expect(() => parseUnified(null)).toThrow('parseUnified: Input must be a string');
      expect(() => parseUnified(undefined)).toThrow('parseUnified: Input must be a string');
      expect(() => parseUnified({})).toThrow('parseUnified: Input must be a string');
    });

    it('should handle empty strings', () => {
      const result = parseUnified('');
      expect(isNormalizedString(result)).toBe(true);
      expect(result.toString()).toBe('');
      expect(result.length).toBe(0);
    });
  });

  describe('parseUnifiedBatch Function', () => {
    it('should parse array of strings', () => {
      const inputs = ['test1', 'test2', 'test3'];
      const results = parseUnifiedBatch(inputs);

      expect(Array.isArray(results)).toBe(true);
      expect(results).toHaveLength(3);
      results.forEach((result, i) => {
        expect(isNormalizedString(result)).toBe(true);
        expect(result.toString()).toBe(inputs[i]);
      });
    });

    it('should throw error for non-array input', () => {
      expect(() => parseUnifiedBatch('not an array')).toThrow('parseUnifiedBatch: Inputs must be an array');
      expect(() => parseUnifiedBatch({ key: 'value' })).toThrow('parseUnifiedBatch: Inputs must be an array');
    });

    it('should handle empty array', () => {
      const results = parseUnifiedBatch([]);
      expect(Array.isArray(results)).toBe(true);
      expect(results).toHaveLength(0);
    });

    it('should propagate options to all parsings', () => {
      const inputs = ['path1', 'path2'];
      const results = parseUnifiedBatch(inputs, { type: 'file_path' });

      results.forEach(result => {
        expect(result.getMetadata().inputType).toBe('file_path');
      });
    });
  });

  describe('isNormalizedString Validator', () => {
    it('should validate NormalizedString instances', () => {
      const ns = parseUnified('test');
      expect(isNormalizedString(ns)).toBe(true);
    });

    it('should reject non-NormalizedString values', () => {
      expect(isNormalizedString('string')).toBe(false);
      expect(isNormalizedString(123)).toBe(false);
      expect(isNormalizedString(null)).toBe(false);
      expect(isNormalizedString(undefined)).toBe(false);
      expect(isNormalizedString({})).toBe(false);
    });
  });

  describe('extractNormalized Function', () => {
    it('should extract from NormalizedString', () => {
      const ns = parseUnified('test string');
      const extracted = extractNormalized(ns);

      expect(typeof extracted).toBe('string');
      expect(extracted).toBe('test string');
    });

    it('should auto-normalize plain strings', () => {
      const extracted = extractNormalized('plain string');

      expect(typeof extracted).toBe('string');
      expect(extracted).toBe('plain string');
    });

    it('should throw error for invalid input', () => {
      expect(() => extractNormalized(123)).toThrow('extractNormalized: Value must be string or NormalizedString');
      expect(() => extractNormalized(null)).toThrow('extractNormalized: Value must be string or NormalizedString');
      expect(() => extractNormalized({})).toThrow('extractNormalized: Value must be string or NormalizedString');
    });
  });

  describe('wrapValidator Function', () => {
    it('should wrap validator to enforce normalization', () => {
      const originalValidator = (input) => {
        return input.length > 5;
      };

      const wrappedValidator = wrapValidator(originalValidator);

      // Test with plain string (should auto-normalize)
      expect(wrappedValidator('short')).toBe(false);
      expect(wrappedValidator('longer string')).toBe(true);

      // Test with NormalizedString
      const ns = parseUnified('wrapped');
      expect(wrappedValidator(ns)).toBe(true);
    });

    it('should throw error for invalid validator input', () => {
      const validator = wrapValidator((input) => input.length > 0);

      expect(() => validator(123)).toThrow('Validator input must be string or NormalizedString');
      expect(() => validator(null)).toThrow('Validator input must be string or NormalizedString');
    });

    it('should preserve validator context', () => {
      const context = { minLength: 5 };
      const validator = wrapValidator(function (input) {
        return input.length >= this.minLength;
      });

      const result = validator.call(context, 'test string');
      expect(result).toBe(true);
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle parser timeout/limits gracefully', () => {
      // Very long input
      const longInput = 'a'.repeat(100000);

      const start = Date.now();
      const result = parseUnified(longInput);
      const elapsed = Date.now() - start;

      expect(isNormalizedString(result)).toBe(true);
      expect(elapsed).toBeLessThan(1000); // Should complete quickly
    });

    it('should handle special characters', () => {
      const specialChars = [
        '\x00\x01\x02', // Control characters
        '\u200B\u200C\u200D', // Zero-width characters
        '\uFEFF', // Byte order mark
        '\\x00\\x00\\x00' // Escaped nulls
      ];

      specialChars.forEach(input => {
        const result = parseUnified(input);
        expect(isNormalizedString(result)).toBe(true);
      });
    });

    it('should prevent TOCTOU vulnerabilities', () => {
      const malicious = '%3Cscript%3Ealert(1)%3C/script%3E';
      const ns = parseUnified(malicious);

      // Normalized string should be consistent
      const first = ns.getNormalized();
      const second = ns.getNormalized();

      expect(first).toBe(second);
      expect(first).not.toBe(malicious);
      expect(ns.getMetadata().parserDifferentialPrevented).toBe(true);
    });

    it('should handle circular reference detection', () => {
      // Parser should not hang on complex patterns
      const complex = '{}'.repeat(1000);

      const start = Date.now();
      const result = parseUnified(complex);
      const elapsed = Date.now() - start;

      expect(isNormalizedString(result)).toBe(true);
      expect(elapsed).toBeLessThan(500);
    });
  });

  describe('CVE-TBD-001 Security Properties', () => {
    it('should mark all parsed strings with security properties', () => {
      const result = parseUnified('test', { type: 'generic' });
      const metadata = result.getMetadata();

      expect(metadata.parserDifferentialPrevented).toBe(true);
      expect(metadata.unifiedParsingVersion).toBe('1.0.0');
      expect(metadata.immutableWrapper).toBe(true);
    });

    it('should ensure single normalization point', () => {
      const input = 'test%20string';
      const result = parseUnified(input);

      // All access should return same normalized value
      expect(result.toString()).toBe(result.getNormalized());
      expect(result.valueOf()).toBe(result.getNormalized());
    });

    it('should prevent access to original string in validation', () => {
      const dangerous = '%3Cscript%3Ealert(1)%3C/script%3E'; // URL encoded
      const ns = parseUnified(dangerous);

      // getNormalized should return decoded version
      const normalized = ns.getNormalized();
      // If decoded, it should be different from original
      const wasDecoded = ns.wasNormalized();
      if (wasDecoded) {
        expect(normalized).not.toBe(dangerous);
      }
      // Metadata should indicate parser differential prevention
      expect(ns.getMetadata().parserDifferentialPrevented).toBe(true);
    });
  });
});
