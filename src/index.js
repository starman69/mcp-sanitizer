/**
 * MCP Sanitizer - Main Entry Point
 *
 * This is the main entry point for the MCP Sanitizer package. It provides
 * a clean, comprehensive API for input validation and sanitization with
 * modular validators and configuration system.
 *
 * The package includes:
 * - Main MCPSanitizer orchestrator class
 * - Modular validators for different input types
 * - Configuration system with security policies
 * - Pattern detection for security threats
 * - Utility functions for common operations
 *
 * @example
 * // Import the main class
 * const MCPSanitizer = require('mcp-sanitizer');
 * const sanitizer = new MCPSanitizer('PRODUCTION');
 *
 * // Use specific validators
 * const { validators } = require('mcp-sanitizer');
 * const urlValidator = new validators.URLValidator();
 *
 * // Use convenience functions
 * const { validateFilePath } = require('mcp-sanitizer');
 * const result = await validateFilePath('/path/to/file.txt');
 */

// Import main sanitizer class
const MCPSanitizer = require('./sanitizer/mcp-sanitizer');

// Import modular validators
const validators = require('./sanitizer/validators');

// Import configuration system
const config = require('./config');

// Import pattern detection
const patterns = require('./patterns');

// Import utilities
const utils = require('./utils');

// Re-export the main class as default export
module.exports = MCPSanitizer;

// Named exports for modular access
module.exports.MCPSanitizer = MCPSanitizer;

// Export validator system
module.exports.validators = validators;

// Export individual validator classes for direct access
module.exports.FilePathValidator = validators.FilePathValidator;
module.exports.URLValidator = validators.URLValidator;
module.exports.CommandValidator = validators.CommandValidator;
module.exports.SQLValidator = validators.SQLValidator;

// Export validator factory functions
module.exports.createFilePathValidator = validators.createFilePathValidator;
module.exports.createURLValidator = validators.createURLValidator;
module.exports.createCommandValidator = validators.createCommandValidator;
module.exports.createSQLValidator = validators.createSQLValidator;
module.exports.createValidator = validators.createValidator;
module.exports.createValidatorManager = validators.createValidatorManager;

// Export convenience validation functions
module.exports.validateFilePath = validators.validateFilePath;
module.exports.sanitizeFilePath = validators.sanitizeFilePath;
module.exports.validateURL = validators.validateURL;
module.exports.sanitizeURL = validators.sanitizeURL;
module.exports.validateCommand = validators.validateCommand;
module.exports.sanitizeCommand = validators.sanitizeCommand;
module.exports.validateSQL = validators.validateSQL;
module.exports.sanitizeSQL = validators.sanitizeSQL;

// Export generic validation functions
module.exports.validate = validators.validate;
module.exports.sanitize = validators.sanitize;
module.exports.validateBatch = validators.validateBatch;
module.exports.sanitizeBatch = validators.sanitizeBatch;

// Export configuration system
module.exports.config = config;
module.exports.createConfig = config.createConfig;
module.exports.createConfigFromPolicy = config.createConfigFromPolicy;
module.exports.createRecommendedConfig = config.createRecommendedConfig;
module.exports.createConfigBuilder = config.createConfigBuilder;

// Export security policies
module.exports.SECURITY_POLICIES = config.SECURITY_POLICIES;
module.exports.POLICY_NAMES = config.POLICY_NAMES;

// Export pattern detection
module.exports.patterns = patterns;
module.exports.detectAllPatterns = patterns.detectAllPatterns;
module.exports.hasSecurityPatterns = patterns.hasSecurityPatterns;
module.exports.analyzeSecurityPatterns = patterns.analyzeSecurityPatterns;

// Export individual pattern detectors
module.exports.commandInjection = patterns.commandInjection;
module.exports.sqlInjection = patterns.sqlInjection;
module.exports.prototypePollution = patterns.prototypePollution;
module.exports.templateInjection = patterns.templateInjection;

// Export utilities
module.exports.utils = utils;
module.exports.stringUtils = utils.stringUtils;
module.exports.objectUtils = utils.objectUtils;
module.exports.validationUtils = utils.validationUtils;

// Export commonly used utility functions
module.exports.htmlEncode = utils.htmlEncode;
module.exports.validateStringLength = utils.validateStringLength;
module.exports.validateAgainstBlockedPatterns = utils.validateAgainstBlockedPatterns;
module.exports.isDangerousKey = utils.isDangerousKey;
module.exports.validateObjectKey = utils.validateObjectKey;
module.exports.validateNonEmptyString = utils.validateNonEmptyString;

// Export new security enhancement functions
module.exports.detectDirectionalOverrides = utils.detectDirectionalOverrides;
module.exports.detectNullBytes = utils.detectNullBytes;
module.exports.detectMultipleUrlEncoding = utils.detectMultipleUrlEncoding;
module.exports.detectPostgresDollarQuotes = utils.detectPostgresDollarQuotes;
module.exports.detectCyrillicHomographs = utils.detectCyrillicHomographs;
module.exports.handleEmptyStrings = utils.handleEmptyStrings;
// Timing consistency removed - not applicable for middleware
// Secure string compare removed - timing attack prevention not applicable
module.exports.comprehensiveSecurityAnalysis = utils.comprehensiveSecurityAnalysis;
module.exports.enhancedStringValidation = utils.enhancedStringValidation;

// Export constants
module.exports.SEVERITY_LEVELS = validators.SEVERITY_LEVELS;
module.exports.VALIDATOR_TYPES = validators.VALIDATOR_TYPES;
module.exports.PATTERN_TYPES = patterns.PATTERN_TYPES;

// Export version information (if available)
try {
  const packageInfo = require('../package.json');
  module.exports.version = packageInfo.version;
  module.exports.name = packageInfo.name;
} catch (error) {
  // Package info not available, skip version export
}

/**
 * Create a pre-configured sanitizer instance for common use cases
 * @param {string} environment - Environment type ('development', 'production', 'testing')
 * @param {Object} customizations - Additional customizations
 * @returns {MCPSanitizer} Configured sanitizer instance
 */
function createSanitizer (environment = 'production', customizations = {}) {
  const policyMap = {
    development: 'DEVELOPMENT',
    dev: 'DEVELOPMENT',
    production: 'PRODUCTION',
    prod: 'PRODUCTION',
    testing: 'PERMISSIVE',
    test: 'PERMISSIVE',
    staging: 'MODERATE'
  };

  const policyName = policyMap[environment.toLowerCase()] || 'PRODUCTION';
  return new MCPSanitizer({ policy: policyName, ...customizations });
}

/**
 * Quick sanitization function for simple string inputs
 * @param {string} input - Input to sanitize
 * @param {Object} options - Sanitization options
 * @returns {Object} Sanitization result
 */
function quickSanitize (input, options = {}) {
  const sanitizer = createSanitizer(options.environment || 'production');
  return sanitizer.sanitize(input, options.context || {});
}

/**
 * Batch sanitization for multiple inputs
 * @param {Array} inputs - Array of inputs to sanitize
 * @param {Object} options - Global options
 * @returns {Array} Array of sanitization results
 */
function batchSanitize (inputs, options = {}) {
  const sanitizer = createSanitizer(options.environment || 'production');
  return inputs.map(input => {
    const inputOptions = typeof input === 'object' && input.options ? input.options : {};
    const inputValue = typeof input === 'object' && input.value !== undefined ? input.value : input;
    const context = typeof input === 'object' && input.context ? input.context : {};

    return sanitizer.sanitize(inputValue, { ...context, ...inputOptions });
  });
}

// Export factory functions
module.exports.createSanitizer = createSanitizer;
module.exports.quickSanitize = quickSanitize;
module.exports.batchSanitize = batchSanitize;

// Export middleware creation function (if middleware directory exists)
try {
  const middleware = require('./middleware');
  module.exports.middleware = middleware;
  module.exports.createMiddleware = middleware.createMiddleware || middleware.create;
} catch (error) {
  // Middleware not available, skip export
}

/**
 * Helper function to check if the package is being used correctly
 * @returns {Object} Package health information
 */
function getPackageInfo () {
  return {
    name: module.exports.name || 'mcp-sanitizer',
    version: module.exports.version || 'unknown',
    modules: {
      validators: Object.keys(validators),
      patterns: Object.keys(patterns),
      config: Object.keys(config),
      utils: Object.keys(utils)
    },
    environment: process.env.NODE_ENV || 'unknown'
  };
}

module.exports.getPackageInfo = getPackageInfo;

/**
 * Compatibility layer for older versions
 * These exports maintain backward compatibility with existing code
 */

// Legacy class name support
module.exports.Sanitizer = MCPSanitizer;
module.exports.MCP = MCPSanitizer;

// Legacy method names
module.exports.sanitizeInput = quickSanitize;
module.exports.sanitizeArray = batchSanitize;

// Legacy pattern detection
module.exports.detectInjection = patterns.detectAllPatterns;
module.exports.hasInjection = patterns.hasSecurityPatterns;

/**
 * TypeScript support - export type definitions if available
 */
try {
  const types = require('./types');
  module.exports.types = types;
} catch (error) {
  // Types not available, skip export
}
