/**
 * MCP Sanitizer Configuration Module
 *
 * This module provides the main configuration interface for the MCP Sanitizer.
 * It combines default configurations, security policies, and configuration
 * management utilities into a single, easy-to-use interface.
 *
 * Usage Examples:
 *
 * // Use default configuration
 * const { createConfig } = require('./src/config');
 * const config = createConfig();
 *
 * // Use a security policy
 * const { createConfigFromPolicy } = require('./src/config');
 * const config = createConfigFromPolicy('PRODUCTION');
 *
 * // Custom configuration
 * const config = createConfig({
 *   maxStringLength: 5000,
 *   allowedProtocols: ['https', 'mcp']
 * });
 *
 * // Policy with customizations
 * const config = createConfigFromPolicy('MODERATE', {
 *   maxStringLength: 8000
 * });
 */

const {
  DEFAULT_CONFIG,
  CONFIG_SCHEMA,
  deepMerge,
  mergeConfig,
  validateConfig,
  createConfig,
  getDefaultConfig
} = require('./default-config');

const {
  SECURITY_POLICIES,
  POLICY_NAMES,
  STRICT_POLICY,
  MODERATE_POLICY,
  PERMISSIVE_POLICY,
  DEVELOPMENT_POLICY,
  PRODUCTION_POLICY,
  getSecurityPolicy,
  createCustomPolicy,
  getPolicyRecommendation,
  validatePolicyRequirements
} = require('./security-policies');

/**
 * Create a configuration from a security policy
 * @param {string} policyName - Name of the security policy to use
 * @param {Object} customizations - Additional customizations to apply
 * @returns {Object} Validated configuration object
 */
function createConfigFromPolicy (policyName, customizations = {}) {
  const policy = getSecurityPolicy(policyName);
  const mergedConfig = mergeConfig({ ...policy, ...customizations });
  validateConfig(mergedConfig);
  return mergedConfig;
}

/**
 * Create a configuration with automatic policy recommendation
 * @param {string} environment - Environment type ('development', 'staging', 'production')
 * @param {string} trustLevel - Trust level ('high', 'medium', 'low')
 * @param {Object} customizations - Additional customizations to apply
 * @returns {Object} Configuration object with metadata
 */
function createRecommendedConfig (environment = 'production', trustLevel = 'low', customizations = {}) {
  const recommendation = getPolicyRecommendation(environment, trustLevel);
  const config = createConfigFromPolicy(recommendation.recommended, customizations);

  return {
    config,
    metadata: {
      recommendedPolicy: recommendation.recommended,
      environment,
      trustLevel,
      rationale: recommendation.rationale
    }
  };
}

/**
 * Configuration builder class for fluent API
 */
class ConfigBuilder {
  constructor () {
    this.config = getDefaultConfig();
  }

  /**
   * Set the base security policy
   * @param {string} policyName - Name of the security policy
   * @returns {ConfigBuilder} Builder instance for chaining
   */
  usePolicy (policyName) {
    const policy = getSecurityPolicy(policyName);
    this.config = mergeConfig(policy);
    return this;
  }

  /**
   * Set allowed protocols
   * @param {string[]} protocols - Array of allowed protocols
   * @returns {ConfigBuilder} Builder instance for chaining
   */
  allowProtocols (protocols) {
    this.config.allowedProtocols = protocols;
    return this;
  }

  /**
   * Set maximum string length
   * @param {number} length - Maximum string length
   * @returns {ConfigBuilder} Builder instance for chaining
   */
  maxStringLength (length) {
    this.config.maxStringLength = length;
    return this;
  }

  /**
   * Set maximum object depth
   * @param {number} depth - Maximum object depth
   * @returns {ConfigBuilder} Builder instance for chaining
   */
  maxDepth (depth) {
    this.config.maxDepth = depth;
    return this;
  }

  /**
   * Set allowed file extensions
   * @param {string[]} extensions - Array of allowed file extensions
   * @returns {ConfigBuilder} Builder instance for chaining
   */
  allowFileExtensions (extensions) {
    this.config.allowedFileExtensions = extensions;
    return this;
  }

  /**
   * Add blocked patterns
   * @param {RegExp[]} patterns - Array of regex patterns to block
   * @returns {ConfigBuilder} Builder instance for chaining
   */
  blockPatterns (patterns) {
    this.config.blockedPatterns = [...this.config.blockedPatterns, ...patterns];
    return this;
  }

  /**
   * Set severity level for automatic blocking
   * @param {string} severity - Severity level ('low', 'medium', 'high', 'critical')
   * @returns {ConfigBuilder} Builder instance for chaining
   */
  blockOnSeverity (severity) {
    this.config.blockOnSeverity = severity;
    return this;
  }

  /**
   * Enable or disable strict mode
   * @param {boolean} enabled - Whether to enable strict mode
   * @returns {ConfigBuilder} Builder instance for chaining
   */
  strictMode (enabled = true) {
    this.config.strictMode = enabled;
    return this;
  }

  /**
   * Configure pattern detection
   * @param {Object} settings - Pattern detection settings
   * @returns {ConfigBuilder} Builder instance for chaining
   */
  patternDetection (settings) {
    this.config.patternDetection = { ...this.config.patternDetection, ...settings };
    return this;
  }

  /**
   * Apply custom configuration
   * @param {Object} customConfig - Custom configuration to merge
   * @returns {ConfigBuilder} Builder instance for chaining
   */
  custom (customConfig) {
    this.config = mergeConfig(this.config, customConfig);
    return this;
  }

  /**
   * Build and validate the configuration
   * @returns {Object} Validated configuration object
   */
  build () {
    validateConfig(this.config);
    return { ...this.config };
  }
}

/**
 * Create a new configuration builder
 * @returns {ConfigBuilder} New configuration builder instance
 */
function createConfigBuilder () {
  return new ConfigBuilder();
}

/**
 * Get configuration summary for debugging/logging
 * @param {Object} config - Configuration to summarize
 * @returns {Object} Configuration summary
 */
function getConfigSummary (config) {
  return {
    security: {
      allowedProtocols: config.allowedProtocols,
      strictMode: config.strictMode,
      blockOnSeverity: config.blockOnSeverity
    },
    limits: {
      maxStringLength: config.maxStringLength,
      maxDepth: config.maxDepth,
      maxArrayLength: config.maxArrayLength,
      maxObjectKeys: config.maxObjectKeys
    },
    fileSystem: {
      allowedFileExtensions: config.allowedFileExtensions?.length || 0,
      allowAbsolutePaths: config.contextSettings?.filePath?.allowAbsolutePaths
    },
    patterns: {
      blockedPatterns: config.blockedPatterns?.length || 0,
      sqlKeywords: config.sqlKeywords?.length || 0,
      blockedCommands: config.blockedCommands?.length || 0
    },
    detection: config.patternDetection,
    performance: config.performance
  };
}

/**
 * Validate configuration compatibility with environment
 * @param {Object} config - Configuration to validate
 * @param {string} environment - Target environment
 * @returns {Object} Validation result with recommendations
 */
function validateEnvironmentCompatibility (config, environment) {
  const result = {
    compatible: true,
    warnings: [],
    recommendations: []
  };

  if (environment === 'production') {
    if (config.allowedProtocols.includes('http')) {
      result.warnings.push('HTTP protocol allowed in production environment');
      result.recommendations.push('Consider using HTTPS only for production');
    }

    if (!config.strictMode) {
      result.warnings.push('Strict mode disabled in production environment');
      result.recommendations.push('Enable strict mode for production security');
    }

    if (config.blockOnSeverity === 'critical') {
      result.warnings.push('Only blocking critical severity in production');
      result.recommendations.push('Consider blocking high severity issues in production');
    }

    if (config.contextSettings?.url?.allowPrivateIPs) {
      result.warnings.push('Private IP access allowed in production');
      result.recommendations.push('Disable private IP access for production security');
    }
  }

  if (environment === 'development') {
    if (config.blockOnSeverity === 'low') {
      result.warnings.push('Blocking low severity issues may hinder development');
      result.recommendations.push('Consider using medium or high severity blocking for development');
    }

    if (config.performance?.timeoutMs < 5000) {
      result.warnings.push('Short timeout may interrupt debugging');
      result.recommendations.push('Consider longer timeout for development environment');
    }
  }

  return result;
}

// Export everything needed for configuration management
module.exports = {
  // Configuration creation functions
  createConfig,
  createConfigFromPolicy,
  createRecommendedConfig,
  createConfigBuilder,

  // Configuration utilities
  deepMerge,
  mergeConfig,
  validateConfig,
  getDefaultConfig,
  getConfigSummary,
  validateEnvironmentCompatibility,

  // Security policy functions
  getSecurityPolicy,
  createCustomPolicy,
  getPolicyRecommendation,
  validatePolicyRequirements,

  // Constants and defaults
  DEFAULT_CONFIG,
  CONFIG_SCHEMA,
  SECURITY_POLICIES,
  POLICY_NAMES,

  // Predefined policies
  STRICT_POLICY,
  MODERATE_POLICY,
  PERMISSIVE_POLICY,
  DEVELOPMENT_POLICY,
  PRODUCTION_POLICY,

  // Builder class
  ConfigBuilder
};
