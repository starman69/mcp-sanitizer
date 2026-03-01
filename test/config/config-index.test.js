/**
 * Coverage tests for config/index.js
 *
 * Targets: createConfigFromPolicy, createRecommendedConfig, ConfigBuilder
 * fluent API, getConfigSummary, validateEnvironmentCompatibility.
 */

const {
  createConfigFromPolicy,
  createRecommendedConfig,
  createConfigBuilder,
  getConfigSummary,
  validateEnvironmentCompatibility,
  ConfigBuilder
} = require('../../src/config');

describe('config/index.js', () => {
  describe('createConfigFromPolicy', () => {
    it('should create config from PRODUCTION policy', () => {
      const config = createConfigFromPolicy('PRODUCTION');
      expect(config).toBeDefined();
      expect(config.allowedProtocols).toContain('https');
    });

    it('should apply customizations over policy', () => {
      const config = createConfigFromPolicy('MODERATE', { maxStringLength: 9999 });
      expect(config.maxStringLength).toBe(9999);
    });
  });

  describe('createRecommendedConfig', () => {
    it('should return config with metadata for production/low', () => {
      const result = createRecommendedConfig('production', 'low');
      expect(result.config).toBeDefined();
      expect(result.metadata.recommendedPolicy).toBe('STRICT');
      expect(result.metadata.environment).toBe('production');
      expect(result.metadata.trustLevel).toBe('low');
      expect(result.metadata.rationale).toContain('STRICT');
    });

    it('should apply customizations', () => {
      const result = createRecommendedConfig('development', 'high', { maxStringLength: 1234 });
      expect(result.config.maxStringLength).toBe(1234);
      expect(result.metadata.recommendedPolicy).toBe('PERMISSIVE');
    });
  });

  describe('ConfigBuilder', () => {
    it('should create a builder instance', () => {
      const builder = createConfigBuilder();
      expect(builder).toBeInstanceOf(ConfigBuilder);
    });

    it('should chain usePolicy', () => {
      const config = createConfigBuilder()
        .usePolicy('STRICT')
        .build();
      expect(config).toBeDefined();
    });

    it('should chain allowProtocols', () => {
      const config = createConfigBuilder()
        .allowProtocols(['https', 'mcp'])
        .build();
      expect(config.allowedProtocols).toEqual(['https', 'mcp']);
    });

    it('should chain maxStringLength', () => {
      const config = createConfigBuilder()
        .maxStringLength(2000)
        .build();
      expect(config.maxStringLength).toBe(2000);
    });

    it('should chain maxDepth', () => {
      const config = createConfigBuilder()
        .maxDepth(5)
        .build();
      expect(config.maxDepth).toBe(5);
    });

    it('should chain allowFileExtensions', () => {
      const config = createConfigBuilder()
        .allowFileExtensions(['.txt', '.md'])
        .build();
      expect(config.allowedFileExtensions).toEqual(['.txt', '.md']);
    });

    it('should chain blockPatterns', () => {
      const config = createConfigBuilder()
        .blockPatterns([/test/])
        .build();
      expect(config.blockedPatterns.some(p => p.source === 'test')).toBe(true);
    });

    it('should chain blockOnSeverity', () => {
      const config = createConfigBuilder()
        .blockOnSeverity('critical')
        .build();
      expect(config.blockOnSeverity).toBe('critical');
    });

    it('should chain strictMode', () => {
      const config = createConfigBuilder()
        .strictMode(true)
        .build();
      expect(config.strictMode).toBe(true);
    });

    it('should chain patternDetection', () => {
      const config = createConfigBuilder()
        .patternDetection({ enableSQLInjection: false })
        .build();
      expect(config.patternDetection.enableSQLInjection).toBe(false);
    });

    it('should chain custom', () => {
      const config = createConfigBuilder()
        .custom({ customField: 'value' })
        .build();
      expect(config.customField).toBe('value');
    });

    it('should support full fluent chain', () => {
      const config = createConfigBuilder()
        .usePolicy('MODERATE')
        .maxStringLength(3000)
        .maxDepth(6)
        .strictMode(false)
        .blockOnSeverity('high')
        .build();
      expect(config.maxStringLength).toBe(3000);
      expect(config.maxDepth).toBe(6);
      expect(config.blockOnSeverity).toBe('high');
    });
  });

  describe('getConfigSummary', () => {
    it('should summarize a config object', () => {
      const config = createConfigFromPolicy('PRODUCTION');
      const summary = getConfigSummary(config);
      expect(summary.security).toBeDefined();
      expect(summary.security.allowedProtocols).toBeDefined();
      expect(summary.limits).toBeDefined();
      expect(summary.limits.maxStringLength).toBeDefined();
      expect(summary.fileSystem).toBeDefined();
      expect(summary.patterns).toBeDefined();
      expect(summary.detection).toBeDefined();
      expect(summary.performance).toBeDefined();
    });

    it('should handle config without optional fields', () => {
      const summary = getConfigSummary({
        allowedProtocols: ['https'],
        strictMode: true,
        blockOnSeverity: 'medium',
        maxStringLength: 1000,
        maxDepth: 3
      });
      expect(summary.fileSystem.allowedFileExtensions).toBe(0);
      expect(summary.patterns.blockedPatterns).toBe(0);
    });
  });

  describe('validateEnvironmentCompatibility', () => {
    it('should warn about HTTP in production', () => {
      const config = createConfigFromPolicy('MODERATE');
      const result = validateEnvironmentCompatibility(config, 'production');
      expect(result.warnings.some(w => w.includes('HTTP'))).toBe(true);
      expect(result.recommendations.length).toBeGreaterThan(0);
    });

    it('should warn about strict mode disabled in production', () => {
      const config = createConfigFromPolicy('MODERATE');
      const result = validateEnvironmentCompatibility(config, 'production');
      expect(result.warnings.some(w => w.includes('Strict mode'))).toBe(true);
    });

    it('should warn about critical-only blocking in production', () => {
      const config = createConfigFromPolicy('PERMISSIVE');
      const result = validateEnvironmentCompatibility(config, 'production');
      expect(result.warnings.some(w => w.includes('critical severity'))).toBe(true);
    });

    it('should warn about private IPs in production', () => {
      const config = createConfigFromPolicy('DEVELOPMENT');
      const result = validateEnvironmentCompatibility(config, 'production');
      expect(result.warnings.some(w => w.includes('Private IP'))).toBe(true);
    });

    it('should have no warnings for STRICT in production', () => {
      const config = createConfigFromPolicy('STRICT');
      const result = validateEnvironmentCompatibility(config, 'production');
      expect(result.warnings).toEqual([]);
    });

    it('should warn about low severity blocking in development', () => {
      const config = { ...createConfigFromPolicy('STRICT'), blockOnSeverity: 'low' };
      const result = validateEnvironmentCompatibility(config, 'development');
      expect(result.warnings.some(w => w.includes('low severity'))).toBe(true);
    });

    it('should warn about short timeout in development', () => {
      const config = createConfigFromPolicy('STRICT');
      const result = validateEnvironmentCompatibility(config, 'development');
      expect(result.warnings.some(w => w.includes('Short timeout'))).toBe(true);
    });
  });
});
