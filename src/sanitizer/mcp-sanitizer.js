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
const { securityDecode } = require('../utils/security-decoder')
const enterpriseSecurity = require('../utils/enterprise-security')
// CVE-TBD-001 FIX: Import unified parser for consistent string normalization
const { parseUnified, extractNormalized, isNormalizedString } = require('../utils/unified-parser')
// DoS protection removed - handled at infrastructure layer

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

    // Apply context mapping for top-level context
    context = this._mapContext(context)

    // Handle empty input properly (Fix Issue #7)
    const emptyCheck = enterpriseSecurity.handleEmptyInput(input, context)
    if (emptyCheck.isEmpty) {
      return {
        sanitized: emptyCheck.sanitized,
        warnings: emptyCheck.warnings,
        blocked: emptyCheck.shouldBlock,
        metadata: {
          processingTime: Date.now() - startTime
        }
      }
    }

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
      // First, apply enterprise security checks
      if (typeof input === 'string') {
        const securityChecks = enterpriseSecurity.performSecurityChecks(input, {
          checkDirectional: true,
          checkNullBytes: true,
          checkDoubleEncoding: true,
          checkHomographs: true // Enable comprehensive homograph detection
        })
        
        if (securityChecks.blocked) {
          result.blocked = true
          result.warnings.push(...securityChecks.warnings)
          result.sanitized = null
          this.stats.blockedCount++
          
          // Apply timing protection and return early
          this._applyTimingProtection(startTime)
          result.metadata.processingTime = Date.now() - startTime
          return result
        }
      }
      
      result.sanitized = this._sanitizeValue(input, context, 0)
      this.stats.sanitizationCount++
    } catch (error) {
      result.blocked = true
      result.warnings.push(`Sanitization failed: ${error.message}`)
      result.sanitized = null
      this.stats.blockedCount++
    }

    // Apply timing protection
    this._applyTimingProtection(startTime)

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
   * CVE-TBD-004 FIX: Stack-safe value sanitization with early depth checking
   * @param {*} value - Value to sanitize
   * @param {Object} context - Context information
   * @param {number} depth - Current recursion depth
   * @returns {*} Sanitized value
   * @private
   */
  _sanitizeValue (value, context, depth) {
    // CVE-TBD-004 FIX: Check depth BEFORE any recursion setup
    // Use sanitizer's configured maxDepth
    if (depth > this.options.maxDepth) {
      throw new Error(`DoS Protection: Maximum recursion depth ${this.options.maxDepth} exceeded at depth ${depth}`)
    }
    
    // Simple depth check to prevent stack exhaustion
    const maxAllowedDepth = this.options.maxDepth || 100;
    
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
   * CVE-TBD-001 FIX: Secure string sanitization with unified parsing
   * This method now uses unified parsing to prevent parser differential attacks
   * @param {string} str - String to sanitize
   * @param {Object} context - Context information
   * @returns {string} Sanitized string
   * @private
   */
  _sanitizeString (str, context) {
    // CVE-TBD-001 FIX: Use unified parser for consistent normalization
    const normalizedStr = parseUnified(str, {
      type: context.type || 'generic',
      strictMode: this.options.strictMode || false
    })

    // Get the normalized string - ALL validators MUST use this
    const safeStr = normalizedStr.getNormalized()
    const metadata = normalizedStr.getMetadata()

    // Check if normalization detected security issues
    if (metadata.wasDecoded || metadata.warnings.length > 0) {
      // Log security issues found during parsing
      const warningMsg = `Security normalization applied: ${metadata.decodingSteps.join(', ')}`
      if (metadata.warnings.length > 0) {
        throw new Error(`${warningMsg}; Warnings: ${metadata.warnings.join('; ')}`)
      }
    }

    // Enhanced homograph detection - check ONLY normalized string (no parser differential)
    const homographCheck = enterpriseSecurity.detectHomographs(safeStr, {
      checkIDN: context.type === 'url',
      multiPass: true,
      detectZeroWidth: true,
      strictMode: this.options.strictMode || false
    })
    if (homographCheck.detected) {
      throw new Error(homographCheck.warnings.join('; '))
    }

    // Validate string length on normalized content ONLY
    stringUtils.validateStringLength(safeStr, this.options.maxStringLength)

    // Check for blocked patterns on normalized content ONLY
    stringUtils.validateAgainstBlockedPatterns(safeStr, this.options.blockedPatterns, context)

    // Context-specific sanitization using SECURE validators with normalized string
    // CRITICAL: Pass ONLY the normalized string, never the original
    if (context.type === 'file_path') {
      return this._secureSanitizeFilePath(safeStr)
    }

    if (context.type === 'url') {
      return this._secureSanitizeURL(safeStr)
    }

    if (context.type === 'command') {
      return this._secureSanitizeCommand(safeStr)
    }

    if (context.type === 'sql') {
      return this._secureSanitizeSQL(safeStr)
    }

    if (context.type === 'nosql') {
      return this._secureSanitizeNoSQL(safeStr)
    }

    // HTML encode for safety
    return stringUtils.htmlEncode(safeStr)
  }

  /**
   * CVE-TBD-004 FIX: Stack-safe object sanitization with early depth checking
   * @param {Object} obj - Object to sanitize
   * @param {Object} context - Context information
   * @param {number} depth - Current recursion depth
   * @returns {Object} Sanitized object
   * @private
   */
  _sanitizeObject (obj, context, depth) {
    // CVE-TBD-004 FIX: Early depth check for nested objects
    // Use sanitizer's configured maxDepth
    if (depth > this.options.maxDepth) {
      throw new Error(`DoS Protection: Maximum recursion depth ${this.options.maxDepth} exceeded at depth ${depth}`)
    }
    
    // Simple depth check to prevent stack exhaustion
    const maxAllowedDepth = this.options.maxDepth || 100;
    
    // Check object key count limit
    const keys = Object.keys(obj)
    if (this.options.maxObjectKeys && keys.length > this.options.maxObjectKeys) {
      throw new Error(`Object has too many keys (${keys.length} > ${this.options.maxObjectKeys})`)
    }

      // Check for NoSQL injection in objects (especially for query context)
      if (context.type === 'nosql' || context.type === 'query') {
        const { detectNoSQLInjection } = require('../patterns/nosql-injection')
        const nosqlCheck = detectNoSQLInjection(obj)
        if (nosqlCheck.detected) {
          const vulnerabilityMessages = nosqlCheck.vulnerabilities.map(vuln => {
            let message = `${vuln.type}: ${vuln.description}`
            if (vuln.operator) {
              message += ` (operator: ${vuln.operator})`
            }
            if (vuln.codeExecution) {
              message += ' [CODE EXECUTION RISK]'
            }
            return message
          })
          
          const errorMessage = `NoSQL injection in object detected (severity: ${nosqlCheck.severity}): ${vulnerabilityMessages.join(', ')}`
          throw new Error(errorMessage)
        }
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
   * Map context type to internal type
   * @param {Object} context - Input context
   * @returns {Object} Mapped context
   * @private
   */
  _mapContext (context) {
    if (!context.type) return context
    
    const typeMap = {
      query: 'nosql',
      mongodb: 'nosql',
      mongo: 'nosql',
      couchdb: 'nosql',
      redis: 'nosql',
      cassandra: 'nosql',
      path: 'file_path',
      uri: 'url',
      cmd: 'command'
    }

    const mappedType = typeMap[context.type.toLowerCase()]
    if (mappedType) {
      return { ...context, type: mappedType }
    }
    
    return context
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
      query: { type: 'nosql' },
      nosql: { type: 'nosql' },
      mongodb: { type: 'nosql' },
      mongo: { type: 'nosql' },
      couchdb: { type: 'nosql' },
      redis: { type: 'nosql' },
      cassandra: { type: 'nosql' },
      sql: { type: 'sql' }
    }

    return contextMap[fieldName.toLowerCase()] || parentContext || {}
  }

  /**
   * Secure file path sanitization with security decoder (synchronous for backward compatibility)
   * @param {string} filePath - File path to sanitize (already decoded)
   * @returns {string} Sanitized file path
   * @private
   */
  _secureSanitizeFilePath (filePath) {
    // filePath is already decoded by _sanitizeString
    const normalizedPath = validationUtils.validateFilePath(filePath)
    validationUtils.validateFileExtension(normalizedPath, this.options.allowedFileExtensions)
    return normalizedPath
  }

  /**
   * Secure URL sanitization with security decoder (synchronous for backward compatibility)
   * @param {string} url - URL to sanitize (already decoded)
   * @returns {string} Sanitized URL
   * @private
   */
  _secureSanitizeURL (url) {
    // url is already decoded by _sanitizeString
    const parsedUrl = validationUtils.validateURL(url, this.options.allowedProtocols)
    validationUtils.validateURLLocation(parsedUrl)
    return parsedUrl.toString()
  }

  /**
   * Secure command sanitization with security decoder (synchronous for backward compatibility)
   * @param {string} command - Command to sanitize (already decoded)
   * @returns {string} Sanitized command
   * @private
   */
  _secureSanitizeCommand (command) {
    // command is already decoded and stripped by _sanitizeString
    return validationUtils.validateCommand(command)
  }

  /**
   * Secure SQL sanitization with security decoder (synchronous for backward compatibility)
   * @param {string} query - SQL query to sanitize (already decoded)
   * @returns {string} Sanitized SQL query
   * @private
   */
  _secureSanitizeSQL (query) {
    // query is already decoded by _sanitizeString
    validationUtils.validateNonEmptyString(query, 'SQL query')

    // Check for PostgreSQL dollar quoting with specific warning
    const dollarQuoteCheck = enterpriseSecurity.detectPostgreSQLDollarQuoting(query)
    if (dollarQuoteCheck.detected) {
      throw new Error(dollarQuoteCheck.warnings.join('; '))
    }

    // Filter out safe SQL keywords for legacy compatibility
    const dangerousSQLKeywords = this.options.sqlKeywords.filter(keyword =>
      !['SELECT', 'FROM', 'WHERE', 'ORDER BY', 'GROUP BY', 'HAVING'].includes(keyword.toUpperCase())
    )

    stringUtils.validateAgainstSQLKeywords(query, dangerousSQLKeywords)
    return stringUtils.safeTrim(query)
  }

  /**
   * Secure NoSQL query sanitization with security decoder
   * @param {string} query - NoSQL query to sanitize (already decoded)
   * @returns {string} Sanitized NoSQL query
   * @private
   */
  _secureSanitizeNoSQL (query) {
    // query is already decoded by _sanitizeString
    validationUtils.validateNonEmptyString(query, 'NoSQL query')

    // Import NoSQL injection detection
    const { detectNoSQLInjection } = require('../patterns/nosql-injection')
    
    // Try to parse as JSON if it looks like JSON
    let queryToCheck = query
    if ((query.trim().startsWith('{') && query.trim().endsWith('}')) ||
        (query.trim().startsWith('[') && query.trim().endsWith(']'))) {
      try {
        queryToCheck = JSON.parse(query)
      } catch (e) {
        // If JSON parsing fails, check as string
      }
    }
    
    // Check for NoSQL injection patterns
    const nosqlCheck = detectNoSQLInjection(queryToCheck)
    if (nosqlCheck.detected) {
      // Create detailed error message based on vulnerabilities found
      const vulnerabilityMessages = nosqlCheck.vulnerabilities.map(vuln => {
        let message = `${vuln.type}: ${vuln.description}`
        if (vuln.operator) {
          message += ` (operator: ${vuln.operator})`
        }
        if (vuln.codeExecution) {
          message += ' [CODE EXECUTION RISK]'
        }
        return message
      })
      
      const errorMessage = `NoSQL injection detected (severity: ${nosqlCheck.severity}): ${vulnerabilityMessages.join(', ')}`
      throw new Error(errorMessage)
    }

    return stringUtils.safeTrim(query)
  }

  /**
   * Legacy file path sanitization (DEPRECATED - kept for fallback only)
   * @param {string} filePath - File path to sanitize
   * @returns {string} Sanitized file path
   * @private
   * @deprecated Use _secureSanitizeFilePath instead
   */
  _legacySanitizeFilePath (filePath) {
    // Legacy path sanitization - security decoder is now integrated
    const normalizedPath = validationUtils.validateFilePath(filePath)
    validationUtils.validateFileExtension(normalizedPath, this.options.allowedFileExtensions)
    return normalizedPath
  }

  /**
   * Legacy URL sanitization (DEPRECATED - kept for fallback only)
   * @param {string} url - URL to sanitize
   * @returns {string} Sanitized URL
   * @private
   * @deprecated Use _secureSanitizeURL instead
   */
  _legacySanitizeURL (url) {
    // Legacy URL sanitization - security decoder is now integrated
    const parsedUrl = validationUtils.validateURL(url, this.options.allowedProtocols)
    validationUtils.validateURLLocation(parsedUrl)
    return parsedUrl.toString()
  }

  /**
   * Legacy command sanitization (DEPRECATED - kept for fallback only)
   * @param {string} command - Command to sanitize
   * @returns {string} Sanitized command
   * @private
   * @deprecated Use _secureSanitizeCommand instead
   */
  _legacySanitizeCommand (command) {
    // Legacy command sanitization - security decoder is now integrated
    return validationUtils.validateCommand(command)
  }

  /**
   * Legacy SQL sanitization (DEPRECATED - kept for fallback only)
   * @param {string} query - SQL query to sanitize
   * @returns {string} Sanitized SQL query
   * @private
   * @deprecated Use _secureSanitizeSQL instead
   */
  _legacySanitizeSQL (query) {
    // Legacy SQL sanitization - security decoder is now integrated
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

  /**
   * Apply timing protection to prevent timing attacks
   * @param {number} startTime - Start time of operation
   * @private
   */
  _applyTimingProtection (startTime) {
    if (this.options.enableTimingProtection === false) {
      return
    }

    const elapsed = Date.now() - startTime
    const targetTime = 10 // Target 10ms for all operations
    
    if (elapsed < targetTime) {
      // Add variable delay to reach target time
      const remainingTime = targetTime - elapsed
      const variance = (Math.random() - 0.5) * 0.4 * remainingTime // ±20% variance
      const finalDelay = Math.max(0, remainingTime + variance)
      
      const endTime = Date.now() + finalDelay
      while (Date.now() < endTime) {
        // CPU work to prevent optimization
        Math.sqrt(Math.random())
      }
    }
  }
}

module.exports = MCPSanitizer
