/**
 * Coverage tests for config/default-config.js
 *
 * Targets: CONFIG_SCHEMA validators for all config fields
 * (allowedProtocols, maxStringLength, maxDepth, maxArrayLength,
 * maxObjectKeys, allowedFileExtensions, blockedPatterns,
 * sqlKeywords, strictMode, logSecurityEvents, blockOnSeverity),
 * deepMerge edge cases.
 */

const {
  DEFAULT_CONFIG,
  CONFIG_SCHEMA,
  createConfig,
  deepMerge
} = require('../../src/config/default-config');

describe('config/default-config.js', () => {
  describe('DEFAULT_CONFIG', () => {
    it('should export default configuration', () => {
      expect(DEFAULT_CONFIG).toBeDefined();
      expect(DEFAULT_CONFIG.allowedProtocols).toBeDefined();
      expect(DEFAULT_CONFIG.maxStringLength).toBeDefined();
    });
  });

  describe('CONFIG_SCHEMA validators', () => {
    it('should reject non-array allowedProtocols', () => {
      expect(() => CONFIG_SCHEMA.allowedProtocols('not-array')).toThrow('must be an array');
    });

    it('should reject non-string protocol values', () => {
      expect(() => CONFIG_SCHEMA.allowedProtocols([123])).toThrow('must be strings');
    });

    it('should accept valid allowedProtocols', () => {
      expect(() => CONFIG_SCHEMA.allowedProtocols(['https', 'http'])).not.toThrow();
    });

    it('should reject negative maxStringLength', () => {
      expect(() => CONFIG_SCHEMA.maxStringLength(-1)).toThrow('non-negative');
    });

    it('should reject non-number maxStringLength', () => {
      expect(() => CONFIG_SCHEMA.maxStringLength('big')).toThrow('non-negative');
    });

    it('should reject negative maxDepth', () => {
      expect(() => CONFIG_SCHEMA.maxDepth(-5)).toThrow('non-negative');
    });

    it('should reject non-number maxDepth', () => {
      expect(() => CONFIG_SCHEMA.maxDepth(null)).toThrow('non-negative');
    });

    it('should reject negative maxArrayLength', () => {
      expect(() => CONFIG_SCHEMA.maxArrayLength(-1)).toThrow('non-negative');
    });

    it('should reject negative maxObjectKeys', () => {
      expect(() => CONFIG_SCHEMA.maxObjectKeys(-1)).toThrow('non-negative');
    });

    it('should reject non-array allowedFileExtensions', () => {
      expect(() => CONFIG_SCHEMA.allowedFileExtensions('txt')).toThrow('must be an array');
    });

    it('should reject extensions not starting with dot', () => {
      expect(() => CONFIG_SCHEMA.allowedFileExtensions(['txt'])).toThrow('starting with a dot');
    });

    it('should accept valid file extensions', () => {
      expect(() => CONFIG_SCHEMA.allowedFileExtensions(['.txt', '.md'])).not.toThrow();
    });

    it('should reject non-array blockedPatterns', () => {
      expect(() => CONFIG_SCHEMA.blockedPatterns('pattern')).toThrow('must be an array');
    });

    it('should reject non-RegExp in blockedPatterns', () => {
      expect(() => CONFIG_SCHEMA.blockedPatterns(['not-regex'])).toThrow('must be RegExp');
    });

    it('should accept valid blockedPatterns', () => {
      expect(() => CONFIG_SCHEMA.blockedPatterns([/test/])).not.toThrow();
    });

    it('should reject non-array sqlKeywords', () => {
      expect(() => CONFIG_SCHEMA.sqlKeywords('SELECT')).toThrow('must be an array');
    });

    it('should reject non-string sqlKeywords', () => {
      expect(() => CONFIG_SCHEMA.sqlKeywords([123])).toThrow('must be strings');
    });

    it('should accept valid sqlKeywords', () => {
      expect(() => CONFIG_SCHEMA.sqlKeywords(['SELECT', 'INSERT'])).not.toThrow();
    });

    it('should reject non-boolean strictMode', () => {
      expect(() => CONFIG_SCHEMA.strictMode('yes')).toThrow('must be a boolean');
    });

    it('should reject non-boolean logSecurityEvents', () => {
      expect(() => CONFIG_SCHEMA.logSecurityEvents(1)).toThrow('must be a boolean');
    });

    it('should reject invalid blockOnSeverity', () => {
      expect(() => CONFIG_SCHEMA.blockOnSeverity('extreme')).toThrow('must be one of');
    });

    it('should accept valid blockOnSeverity', () => {
      expect(() => CONFIG_SCHEMA.blockOnSeverity('medium')).not.toThrow();
    });
  });

  describe('deepMerge', () => {
    it('should handle non-object target', () => {
      const result = deepMerge(null, { a: 1 });
      expect(result.a).toBe(1);
    });

    it('should handle null source', () => {
      const result = deepMerge({ a: 1 }, null);
      expect(result.a).toBe(1);
    });

    it('should clone RegExp values', () => {
      const result = deepMerge({}, { pattern: /test/gi });
      expect(result.pattern).toBeInstanceOf(RegExp);
      expect(result.pattern.source).toBe('test');
    });
  });

  describe('createConfig', () => {
    it('should create config with customizations', () => {
      const config = createConfig({ maxStringLength: 5000 });
      expect(config.maxStringLength).toBe(5000);
    });

    it('should use defaults when no customizations', () => {
      const config = createConfig();
      expect(config.maxStringLength).toBe(DEFAULT_CONFIG.maxStringLength);
    });
  });
});
