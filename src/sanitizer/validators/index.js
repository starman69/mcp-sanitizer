/**
 * MCP Sanitizer Validators Module
 *
 * This module exports all validator classes and utility functions for easy importing.
 * Each validator provides comprehensive validation and sanitization for specific
 * input types, with consistent APIs and return formats.
 *
 * All validators implement the following interface:
 * - validate(input, options): Promise<ValidationResult>
 * - sanitize(input, options): Promise<SanitizationResult>
 * - updateConfig(newConfig): void
 * - getConfig(): Object
 *
 * ValidationResult format:
 * {
 *   isValid: boolean,
 *   sanitized: string|null,
 *   warnings: string[],
 *   severity: 'low'|'medium'|'high'|'critical'|null,
 *   metadata: Object
 * }
 *
 * @example
 * // Import specific validators
 * const { FilePathValidator, URLValidator } = require('./validators');
 *
 * // Import factory functions
 * const { createFilePathValidator, validateURL } = require('./validators');
 *
 * // Import all validators
 * const validators = require('./validators');
 * const fileValidator = new validators.FilePathValidator();
 */

// Import individual validator modules
const filePathValidator = require('./file-path');
const urlValidator = require('./url');
const commandValidator = require('./command');
const sqlValidator = require('./sql');

/**
 * Export all validator classes
 */
const FilePathValidator = filePathValidator.FilePathValidator;
const URLValidator = urlValidator.URLValidator;
const CommandValidator = commandValidator.CommandValidator;
const SQLValidator = sqlValidator.SQLValidator;

/**
 * Export all factory functions
 */
const createFilePathValidator = filePathValidator.createFilePathValidator;
const createURLValidator = urlValidator.createURLValidator;
const createCommandValidator = commandValidator.createCommandValidator;
const createSQLValidator = sqlValidator.createSQLValidator;

/**
 * Export all convenience functions
 */
const validateFilePath = filePathValidator.validateFilePath;
const sanitizeFilePath = filePathValidator.sanitizeFilePath;
const validateURL = urlValidator.validateURL;
const sanitizeURL = urlValidator.sanitizeURL;
const validateCommand = commandValidator.validateCommand;
const sanitizeCommand = commandValidator.sanitizeCommand;
const validateSQL = sqlValidator.validateSQL;
const sanitizeSQL = sqlValidator.sanitizeSQL;

/**
 * Export all constants
 */
const SEVERITY_LEVELS = {
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical'
};

/**
 * Validator type constants for easier identification
 */
const VALIDATOR_TYPES = {
  FILE_PATH: 'file_path',
  URL: 'url',
  COMMAND: 'command',
  SQL: 'sql'
};

/**
 * Default configurations for all validators
 */
const DEFAULT_CONFIGS = {
  filePath: filePathValidator.DEFAULT_CONFIG,
  url: urlValidator.DEFAULT_CONFIG,
  command: commandValidator.DEFAULT_CONFIG,
  sql: sqlValidator.DEFAULT_CONFIG
};

/**
 * Create a validator instance based on type
 * @param {string} type - Validator type (file_path, url, command, sql)
 * @param {Object} config - Optional configuration
 * @returns {Object} Validator instance
 */
function createValidator (type, config = {}) {
  switch (type.toLowerCase()) {
    case VALIDATOR_TYPES.FILE_PATH:
    case 'filepath':
    case 'path':
      return new FilePathValidator(config);

    case VALIDATOR_TYPES.URL:
    case 'uri':
      return new URLValidator(config);

    case VALIDATOR_TYPES.COMMAND:
    case 'cmd':
      return new CommandValidator(config);

    case VALIDATOR_TYPES.SQL:
    case 'query':
      return new SQLValidator(config);

    default:
      throw new Error(`Unknown validator type: ${type}. Supported types: ${Object.values(VALIDATOR_TYPES).join(', ')}`);
  }
}

/**
 * Validate input using appropriate validator based on type
 * @param {string} input - Input to validate
 * @param {string} type - Validator type
 * @param {Object} config - Optional configuration
 * @returns {Promise<Object>} Validation result
 */
async function validate (input, type, config = {}) {
  const validator = createValidator(type, config);
  return await validator.validate(input);
}

/**
 * Sanitize input using appropriate validator based on type
 * @param {string} input - Input to sanitize
 * @param {string} type - Validator type
 * @param {Object} config - Optional configuration
 * @returns {Promise<Object>} Sanitization result
 */
async function sanitize (input, type, config = {}) {
  const validator = createValidator(type, config);
  return await validator.sanitize(input);
}

/**
 * Batch validate multiple inputs of different types
 * @param {Array} inputs - Array of {input, type, config} objects
 * @returns {Promise<Array>} Array of validation results
 */
async function validateBatch (inputs) {
  const results = [];

  for (const { input, type, config = {} } of inputs) {
    try {
      const result = await validate(input, type, config);
      results.push({
        input,
        type,
        ...result
      });
    } catch (error) {
      results.push({
        input,
        type,
        isValid: false,
        sanitized: null,
        warnings: [`Validation error: ${error.message}`],
        severity: SEVERITY_LEVELS.HIGH,
        metadata: { error: error.message }
      });
    }
  }

  return results;
}

/**
 * Batch sanitize multiple inputs of different types
 * @param {Array} inputs - Array of {input, type, config} objects
 * @returns {Promise<Array>} Array of sanitization results
 */
async function sanitizeBatch (inputs) {
  const results = [];

  for (const { input, type, config = {} } of inputs) {
    try {
      const result = await sanitize(input, type, config);
      results.push({
        input,
        type,
        ...result
      });
    } catch (error) {
      results.push({
        input,
        type,
        isValid: false,
        sanitized: null,
        warnings: [`Sanitization error: ${error.message}`],
        severity: SEVERITY_LEVELS.HIGH,
        metadata: { error: error.message }
      });
    }
  }

  return results;
}

/**
 * Get validator configuration by type
 * @param {string} type - Validator type
 * @returns {Object} Default configuration for the validator
 */
function getValidatorConfig (type) {
  switch (type.toLowerCase()) {
    case VALIDATOR_TYPES.FILE_PATH:
    case 'filepath':
    case 'path':
      return { ...DEFAULT_CONFIGS.filePath };

    case VALIDATOR_TYPES.URL:
    case 'uri':
      return { ...DEFAULT_CONFIGS.url };

    case VALIDATOR_TYPES.COMMAND:
    case 'cmd':
      return { ...DEFAULT_CONFIGS.command };

    case VALIDATOR_TYPES.SQL:
    case 'query':
      return { ...DEFAULT_CONFIGS.sql };

    default:
      throw new Error(`Unknown validator type: ${type}`);
  }
}

/**
 * Create a configured validator manager for consistent validation across an application
 * @param {Object} globalConfig - Global configuration to apply to all validators
 * @returns {Object} Validator manager with pre-configured validators
 */
function createValidatorManager (globalConfig = {}) {
  const configs = {
    filePath: { ...DEFAULT_CONFIGS.filePath, ...globalConfig.filePath },
    url: { ...DEFAULT_CONFIGS.url, ...globalConfig.url },
    command: { ...DEFAULT_CONFIGS.command, ...globalConfig.command },
    sql: { ...DEFAULT_CONFIGS.sql, ...globalConfig.sql }
  };

  const validators = {
    filePath: new FilePathValidator(configs.filePath),
    url: new URLValidator(configs.url),
    command: new CommandValidator(configs.command),
    sql: new SQLValidator(configs.sql)
  };

  return {
    // Direct validator access
    validators,

    // Convenience methods
    async validateFilePath (input, options = {}) {
      return await validators.filePath.validate(input, options);
    },

    async sanitizeFilePath (input, options = {}) {
      return await validators.filePath.sanitize(input, options);
    },

    async validateURL (input, options = {}) {
      return await validators.url.validate(input, options);
    },

    async sanitizeURL (input, options = {}) {
      return await validators.url.sanitize(input, options);
    },

    async validateCommand (input, options = {}) {
      return await validators.command.validate(input, options);
    },

    async sanitizeCommand (input, options = {}) {
      return await validators.command.sanitize(input, options);
    },

    async validateSQL (input, options = {}) {
      return await validators.sql.validate(input, options);
    },

    async sanitizeSQL (input, options = {}) {
      return await validators.sql.sanitize(input, options);
    },

    // Generic methods
    async validate (input, type, options = {}) {
      const validator = validators[type] || this._getValidatorByType(type);
      return await validator.validate(input, options);
    },

    async sanitize (input, type, options = {}) {
      const validator = validators[type] || this._getValidatorByType(type);
      return await validator.sanitize(input, options);
    },

    // Update configurations
    updateConfig (type, newConfig) {
      if (validators[type]) {
        validators[type].updateConfig(newConfig);
      }
    },

    updateAllConfigs (newGlobalConfig) {
      Object.keys(validators).forEach(type => {
        if (newGlobalConfig[type]) {
          validators[type].updateConfig(newGlobalConfig[type]);
        }
      });
    },

    // Get configurations
    getConfig (type) {
      return validators[type] ? validators[type].getConfig() : null;
    },

    getAllConfigs () {
      const configs = {};
      Object.keys(validators).forEach(type => {
        configs[type] = validators[type].getConfig();
      });
      return configs;
    },

    // Helper method to get validator by type string
    _getValidatorByType (type) {
      switch (type.toLowerCase()) {
        case VALIDATOR_TYPES.FILE_PATH:
        case 'filepath':
        case 'path':
          return validators.filePath;
        case VALIDATOR_TYPES.URL:
        case 'uri':
          return validators.url;
        case VALIDATOR_TYPES.COMMAND:
        case 'cmd':
          return validators.command;
        case VALIDATOR_TYPES.SQL:
        case 'query':
          return validators.sql;
        default:
          throw new Error(`Unknown validator type: ${type}`);
      }
    }
  };
}

// Export everything
module.exports = {
  // Validator classes
  FilePathValidator,
  URLValidator,
  CommandValidator,
  SQLValidator,

  // Factory functions
  createFilePathValidator,
  createURLValidator,
  createCommandValidator,
  createSQLValidator,
  createValidator,
  createValidatorManager,

  // Convenience functions
  validateFilePath,
  sanitizeFilePath,
  validateURL,
  sanitizeURL,
  validateCommand,
  sanitizeCommand,
  validateSQL,
  sanitizeSQL,

  // Generic functions
  validate,
  sanitize,
  validateBatch,
  sanitizeBatch,

  // Configuration utilities
  getValidatorConfig,

  // Constants
  SEVERITY_LEVELS,
  VALIDATOR_TYPES,
  DEFAULT_CONFIGS,

  // Individual module exports for direct access
  filePathValidator,
  urlValidator,
  commandValidator,
  sqlValidator
};
