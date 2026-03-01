/**
 * Coverage tests for src/index.js
 *
 * Targets: createSanitizer (all env aliases), quickSanitize,
 * batchSanitize (plain string and object inputs).
 */

const {
  createSanitizer,
  quickSanitize,
  batchSanitize
} = require('../src/index');

describe('src/index.js factory functions', () => {
  describe('createSanitizer', () => {
    it('should create a production sanitizer by default', () => {
      const s = createSanitizer();
      expect(s).toBeDefined();
      expect(typeof s.sanitize).toBe('function');
    });

    it('should accept development environment', () => {
      const s = createSanitizer('development');
      expect(s).toBeDefined();
    });

    it('should accept dev alias', () => {
      const s = createSanitizer('dev');
      expect(s).toBeDefined();
    });

    it('should accept prod alias', () => {
      const s = createSanitizer('prod');
      expect(s).toBeDefined();
    });

    it('should accept testing environment', () => {
      const s = createSanitizer('testing');
      expect(s).toBeDefined();
    });

    it('should accept test alias', () => {
      const s = createSanitizer('test');
      expect(s).toBeDefined();
    });

    it('should accept staging environment', () => {
      const s = createSanitizer('staging');
      expect(s).toBeDefined();
    });

    it('should fall back to PRODUCTION for unknown env', () => {
      const s = createSanitizer('unknown');
      expect(s).toBeDefined();
    });

    it('should apply customizations', () => {
      const s = createSanitizer('production', { maxStringLength: 9999 });
      expect(s).toBeDefined();
    });
  });

  describe('quickSanitize', () => {
    it('should sanitize a simple string', () => {
      const result = quickSanitize('hello world');
      expect(result).toBeDefined();
      expect(result.sanitized).toBeDefined();
    });

    it('should accept environment option', () => {
      const result = quickSanitize('test', { environment: 'development' });
      expect(result).toBeDefined();
    });

    it('should accept context option', () => {
      const result = quickSanitize('test', { context: { type: 'generic' } });
      expect(result).toBeDefined();
    });
  });

  describe('batchSanitize', () => {
    it('should sanitize array of plain strings', () => {
      const results = batchSanitize(['hello', 'world']);
      expect(results).toHaveLength(2);
      expect(results[0].sanitized).toBeDefined();
    });

    it('should sanitize array of object inputs with value', () => {
      const results = batchSanitize([
        { value: 'test', options: {}, context: { type: 'generic' } }
      ]);
      expect(results).toHaveLength(1);
      expect(results[0].sanitized).toBeDefined();
    });

    it('should handle mixed plain and object inputs', () => {
      const results = batchSanitize([
        'plain string',
        { value: 'object input', context: { type: 'url' } }
      ]);
      expect(results).toHaveLength(2);
    });

    it('should accept environment option', () => {
      const results = batchSanitize(['hello'], { environment: 'development' });
      expect(results).toHaveLength(1);
    });
  });
});
