/**
 * MCP Sanitizer - Main Orchestrator Class
 *
 * This is the main sanitizer class that orchestrates validation and sanitization
 * using modular validators. It maintains backward compatibility with the original
 * API while providing enhanced functionality through the modular validator system.
 *
 * Features:
 * - Modular validator system with consistent APIs
 * - Configuration system with security policies
 * - Context-aware sanitization
 * - Comprehensive error handling and reporting
 * - Backward compatibility with original API
 * - Performance optimizations
 * - Extensible architecture
 *
 * @example
 * const MCPSanitizer = require('./mcp-sanitizer');
 * const sanitizer = new MCPSanitizer('PRODUCTION');
 *
 * const result = sanitizer.sanitize(userInput, { type: 'file_path' });
 * if (!result.blocked) {
 *   console.log('Sanitized input:', result.sanitized);
 * }
 */

// const path = require('path') // Unused - commented to fix ESLint
// const { URL } = require('url') // Unused - commented to fix ESLint

// Import utility modules
const { stringUtils, objectUtils, validationUtils } = require('../utils')

// Import configuration system
const { createConfig, createConfigFromPolicy } = require('../config')

// Import modular validators
const {
  createValidatorManager,
  SEVERITY_LEVELS
  // VALIDATOR_TYPES // Unused - commented to fix ESLint
} = require('./validators')

// Import pattern detection
const { analyzeSecurityPatterns } = require('../patterns') // detectAllPatterns unused

/**
 * MCP Sanitizer Class
 * Main orchestrator for input validation and sanitization
 */
class MCPSanitizer {
  /**
   * Create a new MCP Sanitizer instance
   * @param {Object|string} options - Configuration options or security policy name
   */
  constructor (options = {}) {
    // Handle different configuration approaches
    if (typeof options === 'string') {
      // If a string is passed, treat it as a security policy name
      this.options = createConfigFromPolicy(options)
    } else if (options.policy) {
      // If policy is specified, use it as base and merge other options
      const { policy, ...customOptions } = options
      this.options = createConfigFromPolicy(policy, customOptions)
    } else {
      // Use default configuration with custom options
      this.options = createConfig(options)
    }

    // Initialize validator manager with configuration
    this.validatorManager = createValidatorManager({
      filePath: this.options.contextSettings?.filePath || {},
      url: this.options.contextSettings?.url || {},
      command: this.options.contextSettings?.command || {},
      sql: this.options.contextSettings?.sql || {}
    })

    // Performance tracking
    this.stats = {
      validationCount: 0,
      sanitizationCount: 0,
      blockedCount: 0,
      warningCount: 0,
      averageProcessingTime: 0
    }
  }

  /**
   * Main sanitization entry point
   * @param {*} input - Input to sanitize
   * @param {Object} context - Sanitization context
   * @returns {Object} Sanitization result
   */
  sanitize (input, context = {}) {
    const startTime = Date.now()

    if (input === null || input === undefined) {
      return {
        sanitized: input,
        warnings: [],
        blocked: false,
        metadata: {
          processingTime: Date.now() - startTime
        }
      }
    }

    const result = {
      sanitized: null,
      warnings: [],
      blocked: false,
      metadata: {
        originalInput: input,
        context,
        processingTime: 0,
        validatorResults: {}
      }
    }

    try {
      result.sanitized = this._sanitizeValue(input, context, 0)
      this.stats.sanitizationCount++
    } catch (error) {
      result.blocked = true
      result.warnings.push(`Sanitization failed: ${error.message}`)
      result.sanitized = null
      this.stats.blockedCount++
    }

    // Update performance stats
    const processingTime = Date.now() - startTime
    result.metadata.processingTime = processingTime
    this._updatePerformanceStats(processingTime)

    if (result.warnings.length > 0) {
      this.stats.warningCount++
    }

    return result
  }

  /**
   * Sanitize file paths using the modular file path validator
   * @param {string} filePath - File path to sanitize
   * @param {Object} options - Additional options
   * @returns {Promise<string>} Sanitized file path
   */
  async sanitizeFilePath (filePath, options = {}) {
    try {
      const result = await this.validatorManager.sanitizeFilePath(filePath, options)

      if (!result.isValid) {
        const error = new Error(result.warnings.join('; '))
        error.severity = result.severity
        throw error
      }

      return result.sanitized
    } catch (error) {
      // Fallback to legacy validation for backward compatibility
      return this._legacySanitizeFilePath(filePath)
    }
  }

  /**
   * Sanitize URLs using the modular URL validator
   * @param {string} url - URL to sanitize
   * @param {Object} options - Additional options
   * @returns {Promise<string>} Sanitized URL
   */
  async sanitizeURL (url, options = {}) {
    try {
      const result = await this.validatorManager.sanitizeURL(url, options)

      if (!result.isValid) {
        const error = new Error(result.warnings.join('; '))
        error.severity = result.severity
        throw error
      }

      return result.sanitized
    } catch (error) {
      // Fallback to legacy validation for backward compatibility
      return this._legacySanitizeURL(url)
    }
  }

  /**
   * Sanitize command strings using the modular command validator
   * @param {string} command - Command to sanitize
   * @param {Object} options - Additional options
   * @returns {Promise<string>} Sanitized command
   */
  async sanitizeCommand (command, options = {}) {
    try {
      const result = await this.validatorManager.sanitizeCommand(command, options)

      if (!result.isValid) {
        const error = new Error(result.warnings.join('; '))
        error.severity = result.severity
        throw error
      }

      return result.sanitized
    } catch (error) {
      // Fallback to legacy validation for backward compatibility
      return this._legacySanitizeCommand(command)
    }
  }

  /**
   * Sanitize SQL queries using the modular SQL validator
   * @param {string} query - SQL query to sanitize
   * @param {Object} options - Additional options
   * @returns {Promise<string>} Sanitized SQL query
   */
  async sanitizeSQL (query, options = {}) {
    try {
      const result = await this.validatorManager.sanitizeSQL(query, options)

      if (!result.isValid) {
        const error = new Error(result.warnings.join('; '))
        error.severity = result.severity
        throw error
      }

      return result.sanitized
    } catch (error) {
      // Fallback to legacy validation for backward compatibility
      return this._legacySanitizeSQL(query)
    }
  }

  /**
   * Enhanced validation method using modular validators
   * @param {*} input - Input to validate
   * @param {string} type - Input type (file_path, url, command, sql)
   * @param {Object} options - Additional options
   * @returns {Promise<Object>} Detailed validation result
   */
  async validate (input, type, options = {}) {
    const startTime = Date.now()

    try {
      const result = await this.validatorManager.validate(input, type, options)

      // Update stats
      this.stats.validationCount++
      if (!result.isValid) {
        this.stats.blockedCount++
      }
      if (result.warnings.length > 0) {
        this.stats.warningCount++
      }

      // Add performance metadata
      result.metadata = result.metadata || {}
      result.metadata.processingTime = Date.now() - startTime

      this._updatePerformanceStats(result.metadata.processingTime)

      return result
    } catch (error) {
      return {
        isValid: false,
        sanitized: null,
        warnings: [`Validation error: ${error.message}`],
        severity: SEVERITY_LEVELS.HIGH,
        metadata: {
          processingTime: Date.now() - startTime,
          error: error.message
        }
      }
    }
  }

  /**
   * Comprehensive security analysis of input
   * @param {*} input - Input to analyze
   * @param {Object} options - Analysis options
   * @returns {Promise<Object>} Security analysis result
   */
  async analyzeInput (input, options = {}) {
    const startTime = Date.now()

    try {
      // Convert input to string for analysis
      const inputString = typeof input === 'string' ? input : JSON.stringify(input)

      // Run comprehensive pattern analysis
      const analysis = analyzeSecurityPatterns(inputString, options)

      // Add additional metadata
      analysis.metadata = {
        ...analysis.metadata,
        processingTime: Date.now() - startTime,
        inputType: typeof input,
        inputLength: inputString.length
      }

      return analysis
    } catch (error) {
      return {
        detected: false,
        severity: null,
        patterns: [],
        recommendations: [`Analysis failed: ${error.message}`],
        riskLevel: 'UNKNOWN',
        shouldBlock: false,
        metadata: {
          processingTime: Date.now() - startTime,
          error: error.message
        }
      }
    }
  }

  /**
   * Get current configuration summary
   * @returns {Object} Configuration summary
   */
  getConfigSummary () {
    const { getConfigSummary } = require('../config')
    return {
      ...getConfigSummary(this.options),
      validators: this.validatorManager.getAllConfigs(),
      stats: { ...this.stats }
    }
  }

  /**
   * Update configuration
   * @param {Object} newOptions - New configuration options to merge
   */
  updateConfig (newOptions) {
    const { mergeConfig, validateConfig } = require('../config')
    this.options = mergeConfig(this.options, newOptions)
    validateConfig(this.options)

    // Update validator configurations
    if (newOptions.contextSettings) {
      this.validatorManager.updateAllConfigs(newOptions.contextSettings)
    }
  }

  /**
   * Apply a security policy to current configuration
   * @param {string} policyName - Name of the security policy
   * @param {Object} customizations - Additional customizations
   */
  applyPolicy (policyName, customizations = {}) {
    const { createConfigFromPolicy } = require('../config')
    this.options = createConfigFromPolicy(policyName, customizations)

    // Recreate validator manager with new configuration
    this.validatorManager = createValidatorManager({
      filePath: this.options.contextSettings?.filePath || {},
      url: this.options.contextSettings?.url || {},
      command: this.options.contextSettings?.command || {},
      sql: this.options.contextSettings?.sql || {}
    })
  }

  /**
   * Check if current configuration is compatible with environment
   * @param {string} environment - Target environment ('development', 'staging', 'production')
   * @returns {Object} Compatibility check result
   */
  checkEnvironmentCompatibility (environment) {
    const { validateEnvironmentCompatibility } = require('../config')
    return validateEnvironmentCompatibility(this.options, environment)
  }

  /**
   * Get performance statistics
   * @returns {Object} Performance statistics
   */
  getStats () {
    return { ...this.stats }
  }

  /**
   * Reset performance statistics
   */
  resetStats () {
    this.stats = {
      validationCount: 0,
      sanitizationCount: 0,
      blockedCount: 0,
      warningCount: 0,
      averageProcessingTime: 0
    }
  }

  /**
   * Private methods for backward compatibility and internal operations
   */

  /**
   * Legacy value sanitization method (maintains backward compatibility)
   * @param {*} value - Value to sanitize
   * @param {Object} context - Context information
   * @param {number} depth - Current recursion depth
   * @returns {*} Sanitized value
   * @private
   */
  _sanitizeValue (value, context, depth) {
    if (depth > this.options.maxDepth) {
      throw new Error(`Maximum object depth exceeded (limit: ${this.options.maxDepth})`)
    }

    if (typeof value === 'string') {
      return this._sanitizeString(value, context)
    }

    if (Array.isArray(value)) {
      // Check array length limit
      if (this.options.maxArrayLength && value.length > this.options.maxArrayLength) {
        throw new Error(`Array length exceeds maximum allowed (${value.length} > ${this.options.maxArrayLength})`)
      }
      return value.map(item => this._sanitizeValue(item, context, depth + 1))
    }

    if (typeof value === 'object' && value !== null) {
      return this._sanitizeObject(value, context, depth)
    }

    return value
  }

  /**
   * Legacy string sanitization method
   * @param {string} str - String to sanitize
   * @param {Object} context - Context information
   * @returns {string} Sanitized string
   * @private
   */
  _sanitizeString (str, context) {
    // Validate string length
    stringUtils.validateStringLength(str, this.options.maxStringLength)

    // Check for blocked patterns
    stringUtils.validateAgainstBlockedPatterns(str, this.options.blockedPatterns)

    // Context-specific sanitization using modular validators (async operations made sync for compatibility)
    if (context.type === 'file_path') {
      return this._legacySanitizeFilePath(str)
    }

    if (context.type === 'url') {
      return this._legacySanitizeURL(str)
    }

    if (context.type === 'command') {
      return this._legacySanitizeCommand(str)
    }

    if (context.type === 'sql') {
      return this._legacySanitizeSQL(str)
    }

    // HTML encode for safety
    return stringUtils.htmlEncode(str)
  }

  /**
   * Legacy object sanitization method
   * @param {Object} obj - Object to sanitize
   * @param {Object} context - Context information
   * @param {number} depth - Current recursion depth
   * @returns {Object} Sanitized object
   * @private
   */
  _sanitizeObject (obj, context, depth) {
    // Check object key count limit
    const keys = Object.keys(obj)
    if (this.options.maxObjectKeys && keys.length > this.options.maxObjectKeys) {
      throw new Error(`Object has too many keys (${keys.length} > ${this.options.maxObjectKeys})`)
    }

    // Check for prototype pollution
    if (typeof obj === 'object' && obj !== null) {
      const proto = Object.getPrototypeOf(obj)
      if (proto !== Object.prototype && proto !== null) {
        const protoKeys = Object.keys(proto)
        const suspiciousKeys = ['isAdmin', 'polluted', 'evil']
        if (protoKeys.some(key => suspiciousKeys.includes(key) ||
            ['admin', 'user', 'auth', 'login', 'permission'].some(sus => key.toLowerCase().includes(sus)))) {
          throw new Error('Prototype pollution detected in object')
        }
      }
    }

    const sanitized = {}

    for (const [key, value] of Object.entries(obj)) {
      // Check for dangerous object keys
      objectUtils.validateObjectKey(key)

      // Determine context for this field
      const fieldContext = this._getFieldContext(key, context)

      sanitized[key] = this._sanitizeValue(value, fieldContext, depth + 1)
    }

    return sanitized
  }

  /**
   * Get field context for object properties
   * @param {string} fieldName - Field name
   * @param {Object} parentContext - Parent context
   * @returns {Object} Field context
   * @private
   */
  _getFieldContext (fieldName, parentContext) {
    const contextMap = {
      file_path: { type: 'file_path' },
      path: { type: 'file_path' },
      url: { type: 'url' },
      uri: { type: 'url' },
      command: { type: 'command' },
      cmd: { type: 'command' },
      query: { type: 'sql' },
      sql: { type: 'sql' }
    }

    return contextMap[fieldName.toLowerCase()] || parentContext || {}
  }

  /**
   * Legacy file path sanitization (synchronous for backward compatibility)
   * @param {string} filePath - File path to sanitize
   * @returns {string} Sanitized file path
   * @private
   */
  _legacySanitizeFilePath (filePath) {
    const normalizedPath = validationUtils.validateFilePath(filePath)
    validationUtils.validateFileExtension(normalizedPath, this.options.allowedFileExtensions)
    return normalizedPath
  }

  /**
   * Legacy URL sanitization (synchronous for backward compatibility)
   * @param {string} url - URL to sanitize
   * @returns {string} Sanitized URL
   * @private
   */
  _legacySanitizeURL (url) {
    const parsedUrl = validationUtils.validateURL(url, this.options.allowedProtocols)
    validationUtils.validateURLLocation(parsedUrl)
    return parsedUrl.toString()
  }

  /**
   * Legacy command sanitization (synchronous for backward compatibility)
   * @param {string} command - Command to sanitize
   * @returns {string} Sanitized command
   * @private
   */
  _legacySanitizeCommand (command) {
    return validationUtils.validateCommand(command)
  }

  /**
   * Legacy SQL sanitization (synchronous for backward compatibility)
   * @param {string} query - SQL query to sanitize
   * @returns {string} Sanitized SQL query
   * @private
   */
  _legacySanitizeSQL (query) {
    validationUtils.validateNonEmptyString(query, 'SQL query')

    // Filter out safe SQL keywords for legacy compatibility
    const dangerousSQLKeywords = this.options.sqlKeywords.filter(keyword =>
      !['SELECT', 'FROM', 'WHERE', 'ORDER BY', 'GROUP BY', 'HAVING'].includes(keyword.toUpperCase())
    )

    stringUtils.validateAgainstSQLKeywords(query, dangerousSQLKeywords)
    return stringUtils.safeTrim(query)
  }

  /**
   * Update performance statistics
   * @param {number} processingTime - Processing time in milliseconds
   * @private
   */
  _updatePerformanceStats (processingTime) {
    const totalOperations = this.stats.validationCount + this.stats.sanitizationCount
    if (totalOperations === 0) {
      this.stats.averageProcessingTime = processingTime
    } else {
      this.stats.averageProcessingTime = (
        (this.stats.averageProcessingTime * (totalOperations - 1) + processingTime) / totalOperations
      )
    }
  }
}

module.exports = MCPSanitizer
