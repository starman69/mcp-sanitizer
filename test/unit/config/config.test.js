/**
 * Configuration System Tests
 *
 * Tests for the MCP Sanitizer configuration system including
 * default configurations, security policies, and configuration
 * validation.
 */

const {
  createConfig,
  createConfigFromPolicy,
  createConfigBuilder,
  mergeConfig,
  validateConfig,
  getDefaultConfig,
  getSecurityPolicy,
  POLICY_NAMES
} = require('../../../src/config');

const MCPSanitizer = require('../../../src/index');

describe('Configuration System', () => {
  describe('Default Configuration', () => {
    test('should create default configuration', () => {
      const config = createConfig();

      expect(config).toHaveProperty('allowedProtocols');
      expect(config).toHaveProperty('maxStringLength');
      expect(config).toHaveProperty('blockedPatterns');
      expect(config).toHaveProperty('sqlKeywords');
      expect(Array.isArray(config.allowedProtocols)).toBe(true);
      expect(Array.isArray(config.blockedPatterns)).toBe(true);
      expect(config.blockedPatterns.every(p => p instanceof RegExp)).toBe(true);
    });

    test('should merge custom options with defaults', () => {
      const config = createConfig({
        maxStringLength: 15000,
        allowedProtocols: ['https', 'mcp']
      });

      expect(config.maxStringLength).toBe(15000);
      expect(config.allowedProtocols).toEqual(['https', 'mcp']);
      expect(config.maxDepth).toBe(10); // Should keep default
    });

    test('should preserve RegExp objects in configuration', () => {
      const config = getDefaultConfig();

      expect(Array.isArray(config.blockedPatterns)).toBe(true);
      expect(config.blockedPatterns.every(p => p instanceof RegExp)).toBe(true);
    });
  });

  describe('Security Policies', () => {
    test('should have all expected policies', () => {
      expect(POLICY_NAMES).toContain('STRICT');
      expect(POLICY_NAMES).toContain('MODERATE');
      expect(POLICY_NAMES).toContain('PERMISSIVE');
      expect(POLICY_NAMES).toContain('DEVELOPMENT');
      expect(POLICY_NAMES).toContain('PRODUCTION');
    });

    test('should get security policy by name', () => {
      const strictPolicy = getSecurityPolicy('STRICT');

      expect(strictPolicy.allowedProtocols).toEqual(['https']);
      expect(strictPolicy.maxStringLength).toBe(1000);
      expect(strictPolicy.strictMode).toBe(true);
      expect(strictPolicy.blockOnSeverity).toBe('medium');
    });

    test('should throw error for invalid policy name', () => {
      expect(() => {
        getSecurityPolicy('INVALID');
      }).toThrow('Invalid security policy');
    });

    test('should create configuration from policy', () => {
      const config = createConfigFromPolicy('MODERATE');

      expect(config.allowedProtocols).toContain('http');
      expect(config.allowedProtocols).toContain('https');
      expect(config.maxStringLength).toBe(5000);
      expect(config.blockOnSeverity).toBe('high');
    });

    test('should merge policy with customizations', () => {
      const config = createConfigFromPolicy('STRICT', {
        maxStringLength: 2000,
        allowedProtocols: ['https', 'mcp']
      });

      expect(config.maxStringLength).toBe(2000);
      expect(config.allowedProtocols).toEqual(['https', 'mcp']);
      expect(config.strictMode).toBe(true); // Should keep from policy
    });
  });

  describe('Configuration Builder', () => {
    test('should build configuration with fluent API', () => {
      const config = createConfigBuilder()
        .usePolicy('MODERATE')
        .maxStringLength(20000)
        .allowProtocols(['https', 'mcp'])
        .strictMode(true)
        .blockOnSeverity('medium')
        .build();

      expect(config.maxStringLength).toBe(20000);
      expect(config.allowedProtocols).toEqual(['https', 'mcp']);
      expect(config.strictMode).toBe(true);
      expect(config.blockOnSeverity).toBe('medium');
    });

    test('should support pattern detection configuration', () => {
      const config = createConfigBuilder()
        .usePolicy('MODERATE')
        .patternDetection({
          enableCommandInjection: true,
          enableSQLInjection: false,
          enableTemplateInjection: false
        })
        .build();

      expect(config.patternDetection.enableCommandInjection).toBe(true);
      expect(config.patternDetection.enableSQLInjection).toBe(false);
      expect(config.patternDetection.enableTemplateInjection).toBe(false);
    });

    test('should support custom configuration merge', () => {
      const config = createConfigBuilder()
        .usePolicy('MODERATE')
        .custom({
          performance: {
            timeoutMs: 10000,
            enableCaching: true
          }
        })
        .build();

      expect(config.performance.timeoutMs).toBe(10000);
      expect(config.performance.enableCaching).toBe(true);
    });
  });

  describe('Configuration Validation', () => {
    test('should validate valid configuration', () => {
      const config = createConfig({
        allowedProtocols: ['https'],
        maxStringLength: 5000,
        maxDepth: 10,
        strictMode: true
      });

      expect(() => validateConfig(config)).not.toThrow();
    });

    test('should throw error for invalid protocol format', () => {
      expect(() => {
        validateConfig({
          allowedProtocols: 'https' // Should be array
        });
      }).toThrow('allowedProtocols must be an array');
    });

    test('should throw error for invalid string length', () => {
      expect(() => {
        validateConfig({
          maxStringLength: -1
        });
      }).toThrow('maxStringLength must be a non-negative number');
    });

    test('should throw error for invalid blocked patterns', () => {
      expect(() => {
        validateConfig({
          blockedPatterns: ['not-a-regex']
        });
      }).toThrow('All blocked patterns must be RegExp objects');
    });
  });

  describe('MCPSanitizer Integration', () => {
    test('should create sanitizer with policy string', () => {
      const sanitizer = new MCPSanitizer('STRICT');
      const summary = sanitizer.getConfigSummary();

      expect(summary.security.allowedProtocols).toEqual(['https']);
      expect(summary.security.strictMode).toBe(true);
      expect(summary.limits.maxStringLength).toBe(1000);
    });

    test('should create sanitizer with policy object', () => {
      const sanitizer = new MCPSanitizer({
        policy: 'MODERATE',
        maxStringLength: 8000
      });
      const summary = sanitizer.getConfigSummary();

      expect(summary.limits.maxStringLength).toBe(8000);
      expect(summary.security.blockOnSeverity).toBe('high');
    });

    test('should update configuration at runtime', () => {
      const sanitizer = new MCPSanitizer('MODERATE');

      sanitizer.updateConfig({
        maxStringLength: 12000,
        allowedProtocols: ['https']
      });

      const summary = sanitizer.getConfigSummary();
      expect(summary.limits.maxStringLength).toBe(12000);
      expect(summary.security.allowedProtocols).toEqual(['https']);
    });

    test('should apply policy at runtime', () => {
      const sanitizer = new MCPSanitizer('PERMISSIVE');

      expect(sanitizer.getConfigSummary().limits.maxStringLength).toBe(50000);

      sanitizer.applyPolicy('STRICT', { maxStringLength: 1500 });

      expect(sanitizer.getConfigSummary().limits.maxStringLength).toBe(1500);
      expect(sanitizer.getConfigSummary().security.strictMode).toBe(true);
    });

    test('should check environment compatibility', () => {
      const sanitizer = new MCPSanitizer('DEVELOPMENT');
      const compatibility = sanitizer.checkEnvironmentCompatibility('production');

      expect(compatibility).toHaveProperty('compatible');
      expect(compatibility).toHaveProperty('warnings');
      expect(compatibility).toHaveProperty('recommendations');
      expect(Array.isArray(compatibility.warnings)).toBe(true);
      expect(Array.isArray(compatibility.recommendations)).toBe(true);
    });
  });

  describe('Configuration Merge', () => {
    test('should merge configurations properly', () => {
      const base = {
        allowedProtocols: ['http', 'https'],
        maxStringLength: 5000,
        contextSettings: {
          url: {
            maxURLLength: 2048
          }
        }
      };

      const custom = {
        allowedProtocols: ['https', 'mcp'],
        maxDepth: 15,
        contextSettings: {
          url: {
            allowPrivateIPs: true
          },
          filePath: {
            allowAbsolutePaths: false
          }
        }
      };

      const merged = mergeConfig(base, custom);

      // Arrays are completely replaced by the custom config
      expect(merged.allowedProtocols).toEqual(['https', 'mcp']);
      expect(merged.maxStringLength).toBe(5000); // From base
      expect(merged.maxDepth).toBe(15); // From custom
      expect(merged.contextSettings.url.maxURLLength).toBe(2048); // From base
      expect(merged.contextSettings.url.allowPrivateIPs).toBe(true); // From custom
      expect(merged.contextSettings.filePath.allowAbsolutePaths).toBe(false); // From custom
    });

    test('should preserve RegExp objects during merge', () => {
      const base = {
        blockedPatterns: [/test1/, /test2/]
      };

      const custom = {
        blockedPatterns: [/test3/, /test4/]
      };

      const merged = mergeConfig(base, custom);

      expect(merged.blockedPatterns).toHaveLength(2);
      expect(merged.blockedPatterns.every(p => p instanceof RegExp)).toBe(true);
      expect(merged.blockedPatterns[0].source).toBe('test3');
      expect(merged.blockedPatterns[1].source).toBe('test4');
    });
  });
});
