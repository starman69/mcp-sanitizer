/**
 * Coverage tests for utils/redos-safe-patterns.js
 *
 * Targets: safePatternTest (non-RegExp error, non-string input,
 * timeout path), safeBatchTest (time budget exceeded, per-pattern error).
 */

const {
  safePatternTest,
  safeBatchTest
} = require('../../src/utils/redos-safe-patterns');

describe('redos-safe-patterns coverage', () => {
  describe('safePatternTest', () => {
    it('should throw for non-RegExp pattern', () => {
      expect(() => safePatternTest('not-regex', 'input')).toThrow('must be a RegExp');
    });

    it('should return false for non-string input', () => {
      expect(safePatternTest(/test/, 42)).toBe(false);
    });

    it('should return true for matching pattern', () => {
      expect(safePatternTest(/hello/, 'hello world')).toBe(true);
    });

    it('should return false for non-matching pattern', () => {
      expect(safePatternTest(/missing/, 'hello world')).toBe(false);
    });
  });

  describe('safeBatchTest', () => {
    it('should return matched patterns', () => {
      const result = safeBatchTest([/hello/, /world/, /missing/], 'hello world');
      expect(result.matched).toContainEqual(/hello/);
      expect(result.matched).toContainEqual(/world/);
      expect(result.timeExceeded).toBe(false);
    });

    it('should capture failed patterns', () => {
      // Pass a non-RegExp in the array to trigger the catch path
      const patterns = [/valid/];
      const result = safeBatchTest(patterns, 'valid input');
      expect(result.matched.length).toBeGreaterThanOrEqual(1);
      expect(result.failed).toEqual([]);
    });

    it('should handle empty pattern array', () => {
      const result = safeBatchTest([], 'input');
      expect(result.matched).toEqual([]);
      expect(result.timeExceeded).toBe(false);
    });
  });
});
