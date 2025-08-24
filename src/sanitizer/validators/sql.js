/**
 * SQL Validator for MCP Sanitizer
 *
 * This module provides comprehensive validation and sanitization for SQL queries,
 * protecting against SQL injection attacks, dangerous SQL operations, and malicious keywords.
 *
 * Features:
 * - SQL injection pattern detection
 * - Dangerous SQL keyword blocking
 * - Query structure validation
 * - Comment and string literal handling
 * - Union and subquery validation
 * - Database function restrictions
 * - Configurable validation rules
 * - Async validation support
 *
 * @example
 * const { SQLValidator } = require('./sql');
 * const validator = new SQLValidator(config);
 *
 * const result = await validator.validate('SELECT * FROM users WHERE id = 1');
 * if (result.isValid) {
 *   console.log('Sanitized SQL:', result.sanitized);
 * } else {
 *   console.error('Validation failed:', result.warnings);
 * }
 */

// const { validationUtils, stringUtils } = require('../../utils') // Unused - commented to fix ESLint
const { sqlInjection, detectAllPatterns, SEVERITY_LEVELS } = require('../../patterns')
const sqlstring = require('sqlstring')
const {
  detectPostgresDollarQuotes,
  detectNullBytes,
  // Timing functions removed
} = require('../../utils/security-enhancements')

/**
 * SQL validation severity levels
 */
const SEVERITY = {
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical'
}

/**
 * Default configuration for SQL validation
 */
const DEFAULT_CONFIG = {
  allowedKeywords: [
    'SELECT', 'FROM', 'WHERE', 'ORDER BY', 'GROUP BY', 'HAVING',
    'INNER JOIN', 'LEFT JOIN', 'RIGHT JOIN', 'FULL JOIN',
    'UNION', 'UNION ALL', 'AS', 'DISTINCT', 'TOP', 'LIMIT'
  ],
  blockedKeywords: [
    'DROP', 'DELETE', 'UPDATE', 'INSERT', 'CREATE', 'ALTER',
    'TRUNCATE', 'EXEC', 'EXECUTE', 'SP_', 'XP_',
    'LOAD_FILE', 'INTO OUTFILE', 'INTO DUMPFILE',
    'INFORMATION_SCHEMA', 'MYSQL.USER', 'SYS',
    'BENCHMARK', 'SLEEP', 'WAITFOR'
  ],
  allowComments: false,
  allowUnions: true,
  allowSubqueries: true,
  allowFunctions: ['COUNT', 'SUM', 'AVG', 'MIN', 'MAX', 'COALESCE', 'ISNULL'],
  blockedFunctions: [
    'LOAD_FILE', 'INTO_OUTFILE', 'CHAR', 'ASCII', 'ORD',
    'SUBSTRING', 'CONCAT_WS', 'MAKE_SET', 'EXPORT_SET',
    'BENCHMARK', 'SLEEP', 'GET_LOCK', 'RELEASE_LOCK',
    'USER', 'DATABASE', 'VERSION', 'CONNECTION_ID'
  ],
  maxQueryLength: 5000,
  maxUnions: 3,
  maxSubqueries: 5,
  maxParameters: 50,
  allowStringLiterals: true,
  allowNumericLiterals: true,
  allowWildcards: true,
  strictMode: false,
  databaseType: 'generic', // mysql, postgresql, sqlite, mssql, oracle
  customPatterns: []
}

/**
 * SQL injection patterns specific to this validator
 */
const SQL_INJECTION_PATTERNS = [
  /('|(\\))|(\s*(or|and)\s+[\w\s]*[=<>]+)/i, // Basic SQL injection
  /union\s+select/i, // Union-based injection
  /;\s*(drop|delete|update|insert)/i, // Stacked queries
  /\/\*.*?\*\//gs, // Block comments
  /--[\s\S]*?$/gm, // Line comments
  /#[\s\S]*?$/gm, // MySQL comments
  /\bchar\s*\(/i, // CHAR function
  /\bascii\s*\(/i, // ASCII function
  /\bbenchmark\s*\(/i, // BENCHMARK function
  /\bsleep\s*\(/i, // SLEEP function
  /\bwaitfor\s+delay/i, // WAITFOR DELAY
  /information_schema/i, // Information schema
  /\bload_file\s*\(/i, // LOAD_FILE function
  /into\s+(outfile|dumpfile)/i, // File operations
  /\bsp_\w+/i, // Stored procedures
  /\bxp_\w+/i // Extended procedures
]

/**
 * Database-specific dangerous patterns
 */
const DATABASE_SPECIFIC_PATTERNS = {
  mysql: [
    /mysql\.user/i,
    /load_file\s*\(/i,
    /into\s+outfile/i,
    /benchmark\s*\(/i,
    /sleep\s*\(/i
  ],
  postgresql: [
    /pg_sleep\s*\(/i,
    /pg_user/i,
    /current_database\s*\(/i,
    /version\s*\(/i
  ],
  mssql: [
    /xp_cmdshell/i,
    /sp_\w+/i,
    /openrowset/i,
    /opendatasource/i,
    /waitfor\s+delay/i
  ],
  oracle: [
    /dbms_\w+/i,
    /utl_\w+/i,
    /sys\./i,
    /dual/i
  ],
  sqlite: [
    /sqlite_master/i,
    /pragma/i,
    /attach\s+database/i
  ]
}

/**
 * SQL Validator Class
 */
class SQLValidator {
  /**
   * Create a new SQL validator
   * @param {Object} config - Validation configuration
   */
  constructor (config = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config }
  }

  /**
   * Validate a SQL query
   * @param {string} query - The SQL query to validate
   * @param {Object} options - Additional validation options
   * @returns {Promise<Object>} Validation result
   */
  async validate (query, options = {}) {
    // Timing consistency removed - not applicable for middleware sanitization
    return this._performValidation(query, options)
  }

  /**
   * Internal validation method
   * @private
   */
  async _performValidation (query, options = {}) {
    const result = {
      isValid: false,
      sanitized: null,
      warnings: [],
      severity: null,
      metadata: {
        originalQuery: query,
        normalizedQuery: null,
        detectedKeywords: [],
        detectedFunctions: [],
        unionCount: 0,
        subqueryCount: 0,
        commentCount: 0,
        detectedPatterns: []
      }
    }

    try {
      // Basic input validation
      if (typeof query !== 'string') {
        result.warnings.push('SQL query must be a string')
        result.severity = SEVERITY.HIGH
        return result
      }

      if (!query || query.trim().length === 0) {
        result.warnings.push('SQL query cannot be empty')
        result.severity = SEVERITY.HIGH
        return result
      }

      // Check query length
      if (query.length > this.config.maxQueryLength) {
        result.warnings.push(`SQL query exceeds maximum length of ${this.config.maxQueryLength} characters`)
        result.severity = SEVERITY.MEDIUM
        return result
      }

      const trimmedQuery = query.trim()
      const normalizedQuery = this._normalizeQuery(trimmedQuery)
      result.metadata.normalizedQuery = normalizedQuery

      // Enhanced SQL security checks
      
      // Check for null bytes
      const nullByteResult = detectNullBytes(trimmedQuery)
      if (nullByteResult.detected) {
        result.warnings.push(...nullByteResult.warnings.map(w => w.message || w))
        result.metadata.nullBytes = nullByteResult.metadata
        result.severity = this._getHigherSeverity(result.severity, SEVERITY.HIGH)
        
        // Use sanitized version without null bytes
        trimmedQuery = nullByteResult.sanitized
      }

      // Check for PostgreSQL dollar quotes
      const dollarQuoteResult = detectPostgresDollarQuotes(trimmedQuery)
      if (dollarQuoteResult.detected) {
        result.warnings.push(...dollarQuoteResult.warnings.map(w => w.message || w))
        result.metadata.postgresDollarQuotes = dollarQuoteResult.metadata
        
        // Check for critical severity (unpaired quotes or SQL in quotes)
        const hasCriticalWarnings = dollarQuoteResult.warnings.some(w => w.severity === 'HIGH')
        if (hasCriticalWarnings) {
          result.severity = this._getHigherSeverity(result.severity, SEVERITY.HIGH)
        } else {
          result.severity = this._getHigherSeverity(result.severity, SEVERITY.MEDIUM)
        }
      }

      // Check for SQL injection patterns using the pattern detector
      const injectionResult = sqlInjection.detectSQLInjection(trimmedQuery)
      if (injectionResult.detected) {
        result.metadata.detectedPatterns = injectionResult.patterns
        result.warnings.push(`SQL injection patterns detected: ${injectionResult.patterns.join(', ')}`)
        result.severity = this._mapSeverity(injectionResult.severity)

        if (injectionResult.severity === SEVERITY_LEVELS.CRITICAL) {
          return result
        }
      }

      // Run general pattern detection
      const patternResult = detectAllPatterns(trimmedQuery)
      if (patternResult.detected) {
        result.metadata.detectedPatterns.push(...patternResult.patterns)
        result.warnings.push(`Additional security patterns detected: ${patternResult.patterns.join(', ')}`)
        result.severity = this._getHigherSeverity(result.severity, this._mapSeverity(patternResult.severity))
      }

      // Check for additional SQL-specific injection patterns
      const customPatternResult = this._checkCustomPatterns(normalizedQuery)
      if (!customPatternResult.isValid) {
        result.warnings.push(...customPatternResult.warnings)
        result.severity = this._getHigherSeverity(result.severity, customPatternResult.severity)

        if (customPatternResult.severity === SEVERITY.CRITICAL) {
          return result
        }
      }

      // Validate SQL keywords
      const keywordResult = this._validateKeywords(normalizedQuery)
      if (!keywordResult.isValid) {
        result.warnings.push(...keywordResult.warnings)
        result.severity = this._getHigherSeverity(result.severity, keywordResult.severity)

        if (keywordResult.severity === SEVERITY.CRITICAL) {
          return result
        }
      }
      result.metadata.detectedKeywords = keywordResult.detectedKeywords

      // Validate SQL functions
      const functionResult = this._validateFunctions(normalizedQuery)
      if (!functionResult.isValid) {
        result.warnings.push(...functionResult.warnings)
        result.severity = this._getHigherSeverity(result.severity, functionResult.severity)

        if (functionResult.severity === SEVERITY.CRITICAL) {
          return result
        }
      }
      result.metadata.detectedFunctions = functionResult.detectedFunctions

      // Validate comments
      const commentResult = this._validateComments(trimmedQuery)
      if (!commentResult.isValid) {
        result.warnings.push(...commentResult.warnings)
        result.severity = this._getHigherSeverity(result.severity, commentResult.severity)

        if (commentResult.severity === SEVERITY.CRITICAL) {
          return result
        }
      }
      result.metadata.commentCount = commentResult.commentCount

      // Validate UNION operations
      const unionResult = this._validateUnions(normalizedQuery)
      if (!unionResult.isValid) {
        result.warnings.push(...unionResult.warnings)
        result.severity = this._getHigherSeverity(result.severity, unionResult.severity)

        if (unionResult.severity === SEVERITY.CRITICAL) {
          return result
        }
      }
      result.metadata.unionCount = unionResult.unionCount

      // Validate subqueries
      const subqueryResult = this._validateSubqueries(normalizedQuery)
      if (!subqueryResult.isValid) {
        result.warnings.push(...subqueryResult.warnings)
        result.severity = this._getHigherSeverity(result.severity, subqueryResult.severity)

        if (subqueryResult.severity === SEVERITY.CRITICAL) {
          return result
        }
      }
      result.metadata.subqueryCount = subqueryResult.subqueryCount

      // Database-specific validation
      const dbResult = this._validateDatabaseSpecific(normalizedQuery)
      if (!dbResult.isValid) {
        result.warnings.push(...dbResult.warnings)
        result.severity = this._getHigherSeverity(result.severity, dbResult.severity)

        if (dbResult.severity === SEVERITY.CRITICAL) {
          return result
        }
      }

      // Validate string and numeric literals
      const literalResult = this._validateLiterals(trimmedQuery)
      if (!literalResult.isValid) {
        result.warnings.push(...literalResult.warnings)
        result.severity = this._getHigherSeverity(result.severity, literalResult.severity)
      }

      // If we get here, the query is valid
      result.isValid = true
      result.sanitized = trimmedQuery

      // Set severity to lowest if there were warnings but query is still valid
      if (result.warnings.length === 0) {
        result.severity = null
      } else if (!result.severity) {
        result.severity = SEVERITY.LOW
      }
    } catch (error) {
      result.warnings.push(`Validation error: ${error.message}`)
      result.severity = SEVERITY.HIGH
    }

    return result
  }

  /**
   * Sanitize a SQL query
   * @param {string} query - The SQL query to sanitize
   * @param {Object} options - Sanitization options
   * @returns {Promise<Object>} Sanitization result
   */
  async sanitize (query, options = {}) {
    const validationResult = await this.validate(query, options)

    if (validationResult.isValid) {
      return validationResult
    }

    // Attempt to sanitize the query
    let sanitized = query
    const warnings = [...validationResult.warnings]

    try {
      // Basic sanitization
      sanitized = sanitized.trim()

      // Remove comments if not allowed
      if (!this.config.allowComments) {
        sanitized = this._removeComments(sanitized)
        warnings.push('Removed SQL comments')
      }

      // Remove dangerous keywords by replacing with safe alternatives or comments
      sanitized = this._sanitizeKeywords(sanitized)
      if (sanitized !== query.trim()) {
        warnings.push('Sanitized dangerous SQL keywords')
      }

      // Remove or replace dangerous functions
      sanitized = this._sanitizeFunctions(sanitized)
      if (sanitized !== query.trim()) {
        warnings.push('Sanitized dangerous SQL functions')
      }

      // Limit string literal length
      sanitized = this._sanitizeStringLiterals(sanitized)

      // Remove excess UNION operations
      sanitized = this._limitUnions(sanitized)
      if (sanitized !== query.trim()) {
        warnings.push(`Limited UNION operations to ${this.config.maxUnions}`)
      }

      // If query becomes too short or empty after sanitization, reject it
      if (!sanitized || sanitized.length < 5) {
        return {
          isValid: false,
          sanitized: null,
          warnings: [...warnings, 'Query became too short or empty after sanitization'],
          severity: SEVERITY.HIGH,
          metadata: {
            ...validationResult.metadata,
            wasSanitized: false,
            sanitizationFailed: true
          }
        }
      }

      // Re-validate the sanitized query
      const revalidationResult = await this.validate(sanitized, options)

      return {
        isValid: revalidationResult.isValid,
        sanitized: revalidationResult.isValid ? revalidationResult.sanitized : null,
        warnings: [...warnings, ...revalidationResult.warnings],
        severity: this._getHigherSeverity(validationResult.severity, revalidationResult.severity),
        metadata: {
          ...validationResult.metadata,
          ...revalidationResult.metadata,
          wasSanitized: true,
          sanitizationApplied: true
        }
      }
    } catch (error) {
      return {
        isValid: false,
        sanitized: null,
        warnings: [...warnings, `Sanitization failed: ${error.message}`],
        severity: SEVERITY.HIGH,
        metadata: {
          ...validationResult.metadata,
          wasSanitized: false,
          sanitizationError: error.message
        }
      }
    }
  }

  /**
   * Normalize SQL query for consistent analysis
   * @param {string} query - Query to normalize
   * @returns {string} Normalized query
   * @private
   */
  _normalizeQuery (query) {
    return query
      .replace(/\s+/g, ' ') // Normalize whitespace
      .replace(/\n/g, ' ') // Remove newlines
      .replace(/\t/g, ' ') // Remove tabs
      .toUpperCase() // Convert to uppercase for keyword matching
      .trim()
  }

  /**
   * Check for custom SQL injection patterns
   * @param {string} query - Query to check
   * @returns {Object} Check result
   * @private
   */
  _checkCustomPatterns (query) {
    const result = {
      isValid: true,
      warnings: [],
      severity: null
    }

    // Check built-in SQL injection patterns
    for (const pattern of SQL_INJECTION_PATTERNS) {
      if (pattern.test(query)) {
        result.isValid = false
        result.warnings.push(`SQL injection pattern detected: ${pattern.source}`)
        result.severity = SEVERITY.CRITICAL
      }
    }

    // Check custom patterns from configuration
    for (const pattern of this.config.customPatterns) {
      if (pattern.test && pattern.test(query)) {
        result.warnings.push(`Custom SQL pattern detected: ${pattern.source || pattern}`)
        result.severity = this._getHigherSeverity(result.severity, SEVERITY.MEDIUM)
      }
    }

    return result
  }

  /**
   * Validate SQL keywords
   * @param {string} query - Query to validate
   * @returns {Object} Validation result
   * @private
   */
  _validateKeywords (query) {
    const result = {
      isValid: true,
      warnings: [],
      severity: null,
      detectedKeywords: []
    }

    // Check for blocked keywords
    for (const keyword of this.config.blockedKeywords) {
      const pattern = new RegExp(`\\b${keyword}\\b`, 'i')
      if (pattern.test(query)) {
        result.isValid = false
        result.warnings.push(`Blocked SQL keyword detected: ${keyword}`)
        result.severity = SEVERITY.CRITICAL
        result.detectedKeywords.push(keyword)
      }
    }

    // If allowedKeywords is specified, check against it
    if (this.config.allowedKeywords.length > 0) {
      const words = query.split(/\s+/)
      for (const word of words) {
        const cleanWord = word.replace(/[^\w]/g, '')
        if (cleanWord.length > 2) { // Only check substantial words
          let isAllowed = false

          for (const allowedKeyword of this.config.allowedKeywords) {
            if (cleanWord.toUpperCase().includes(allowedKeyword.toUpperCase())) {
              isAllowed = true
              break
            }
          }

          if (!isAllowed && this._isSQLKeyword(cleanWord)) {
            result.warnings.push(`SQL keyword '${cleanWord}' is not in allowed list`)
            result.severity = this._getHigherSeverity(result.severity, SEVERITY.MEDIUM)
          }
        }
      }
    }

    return result
  }

  /**
   * Check if a word is a SQL keyword
   * @param {string} word - Word to check
   * @returns {boolean} True if it's a SQL keyword
   * @private
   */
  _isSQLKeyword (word) {
    const commonSQLKeywords = [
      'SELECT', 'FROM', 'WHERE', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP',
      'ALTER', 'TABLE', 'INDEX', 'VIEW', 'DATABASE', 'SCHEMA', 'PROCEDURE',
      'FUNCTION', 'TRIGGER', 'UNION', 'JOIN', 'LEFT', 'RIGHT', 'INNER', 'OUTER',
      'ORDER', 'GROUP', 'HAVING', 'DISTINCT', 'COUNT', 'SUM', 'AVG', 'MIN', 'MAX'
    ]

    return commonSQLKeywords.includes(word.toUpperCase())
  }

  /**
   * Validate SQL functions
   * @param {string} query - Query to validate
   * @returns {Object} Validation result
   * @private
   */
  _validateFunctions (query) {
    const result = {
      isValid: true,
      warnings: [],
      severity: null,
      detectedFunctions: []
    }

    // Check for blocked functions
    for (const func of this.config.blockedFunctions) {
      const pattern = new RegExp(`\\b${func}\\s*\\(`, 'i')
      if (pattern.test(query)) {
        result.isValid = false
        result.warnings.push(`Blocked SQL function detected: ${func}`)
        result.severity = SEVERITY.CRITICAL
        result.detectedFunctions.push(func)
      }
    }

    // If allowedFunctions is specified, check against it
    if (this.config.allowedFunctions.length > 0) {
      const functionMatches = query.match(/\b\w+\s*\(/g)
      if (functionMatches) {
        for (const match of functionMatches) {
          const funcName = match.replace(/\s*\(.*$/, '').trim()
          if (!this.config.allowedFunctions.some(allowed =>
            funcName.toUpperCase().includes(allowed.toUpperCase()))) {
            result.warnings.push(`SQL function '${funcName}' is not in allowed list`)
            result.severity = this._getHigherSeverity(result.severity, SEVERITY.MEDIUM)
          }
        }
      }
    }

    return result
  }

  /**
   * Validate SQL comments
   * @param {string} query - Query to validate
   * @returns {Object} Validation result
   * @private
   */
  _validateComments (query) {
    const result = {
      isValid: true,
      warnings: [],
      severity: null,
      commentCount: 0
    }

    if (!this.config.allowComments) {
      // Check for various comment types
      const commentPatterns = [
        /\/\*.*?\*\//gs, // Block comments
        /--.*$/gm, // SQL line comments
        /#.*$/gm // MySQL comments
      ]

      for (const pattern of commentPatterns) {
        const matches = query.match(pattern)
        if (matches) {
          result.isValid = false
          result.commentCount += matches.length
          result.warnings.push(`SQL comments detected (${matches.length} found)`)
          result.severity = SEVERITY.HIGH
        }
      }
    }

    return result
  }

  /**
   * Validate UNION operations
   * @param {string} query - Query to validate
   * @returns {Object} Validation result
   * @private
   */
  _validateUnions (query) {
    const result = {
      isValid: true,
      warnings: [],
      severity: null,
      unionCount: 0
    }

    const unionMatches = query.match(/\bUNION(\s+ALL)?\b/gi)
    result.unionCount = unionMatches ? unionMatches.length : 0

    if (!this.config.allowUnions && result.unionCount > 0) {
      result.isValid = false
      result.warnings.push('UNION operations are not allowed')
      result.severity = SEVERITY.HIGH
    } else if (result.unionCount > this.config.maxUnions) {
      result.isValid = false
      result.warnings.push(`Too many UNION operations (${result.unionCount} > ${this.config.maxUnions})`)
      result.severity = SEVERITY.HIGH
    }

    return result
  }

  /**
   * Validate subqueries
   * @param {string} query - Query to validate
   * @returns {Object} Validation result
   * @private
   */
  _validateSubqueries (query) {
    const result = {
      isValid: true,
      warnings: [],
      severity: null,
      subqueryCount: 0
    }

    // Count nested parentheses as a proxy for subqueries
    let depth = 0
    let maxDepth = 0

    for (let i = 0; i < query.length; i++) {
      if (query[i] === '(') {
        depth++
        maxDepth = Math.max(maxDepth, depth)
      } else if (query[i] === ')') {
        depth--
      }
    }

    result.subqueryCount = maxDepth

    if (!this.config.allowSubqueries && result.subqueryCount > 0) {
      result.isValid = false
      result.warnings.push('Subqueries are not allowed')
      result.severity = SEVERITY.HIGH
    } else if (result.subqueryCount > this.config.maxSubqueries) {
      result.isValid = false
      result.warnings.push(`Too many nested subqueries (${result.subqueryCount} > ${this.config.maxSubqueries})`)
      result.severity = SEVERITY.HIGH
    }

    return result
  }

  /**
   * Validate database-specific patterns
   * @param {string} query - Query to validate
   * @returns {Object} Validation result
   * @private
   */
  _validateDatabaseSpecific (query) {
    const result = {
      isValid: true,
      warnings: [],
      severity: null
    }

    const patterns = DATABASE_SPECIFIC_PATTERNS[this.config.databaseType]
    if (patterns) {
      for (const pattern of patterns) {
        if (pattern.test(query)) {
          result.isValid = false
          result.warnings.push(`Database-specific dangerous pattern detected for ${this.config.databaseType}: ${pattern.source}`)
          result.severity = SEVERITY.CRITICAL
        }
      }
    }

    return result
  }

  /**
   * Validate string and numeric literals
   * @param {string} query - Query to validate
   * @returns {Object} Validation result
   * @private
   */
  _validateLiterals (query) {
    const result = {
      isValid: true,
      warnings: [],
      severity: null
    }

    if (!this.config.allowStringLiterals) {
      const stringLiterals = query.match(/'[^']*'/g)
      if (stringLiterals) {
        result.warnings.push(`String literals detected (${stringLiterals.length} found)`)
        result.severity = SEVERITY.MEDIUM
      }
    }

    // Check for very long string literals that might be injection attempts
    const longStringPattern = /'[^']{100,}'/g
    const longStrings = query.match(longStringPattern)
    if (longStrings) {
      result.warnings.push('Very long string literals detected (potential injection)')
      result.severity = this._getHigherSeverity(result.severity, SEVERITY.HIGH)
    }

    return result
  }

  /**
   * Remove SQL comments from query
   * @param {string} query - Query to process
   * @returns {string} Query with comments removed
   * @private
   */
  _removeComments (query) {
    return query
      .replace(/\/\*.*?\*\//gs, ' ') // Block comments
      .replace(/--.*$/gm, '') // Line comments
      .replace(/#.*$/gm, '') // MySQL comments
      .replace(/\s+/g, ' ') // Normalize whitespace
      .trim()
  }

  /**
   * Sanitize dangerous keywords by commenting them out or replacing
   * @param {string} query - Query to sanitize
   * @returns {string} Sanitized query
   * @private
   */
  _sanitizeKeywords (query) {
    let sanitized = query

    for (const keyword of this.config.blockedKeywords) {
      const pattern = new RegExp(`\\b${keyword}\\b`, 'gi')
      sanitized = sanitized.replace(pattern, `/* ${keyword} */`)
    }

    return sanitized
  }

  /**
   * Sanitize dangerous functions
   * @param {string} query - Query to sanitize
   * @returns {string} Sanitized query
   * @private
   */
  _sanitizeFunctions (query) {
    let sanitized = query

    for (const func of this.config.blockedFunctions) {
      const pattern = new RegExp(`\\b${func}\\s*\\(`, 'gi')
      sanitized = sanitized.replace(pattern, `/* ${func} */(`)
    }

    return sanitized
  }

  /**
   * Sanitize string literals by limiting their length
   * @param {string} query - Query to sanitize
   * @returns {string} Sanitized query
   * @private
   */
  _sanitizeStringLiterals (query) {
    return query.replace(/'([^']{100,})'/g, (match, content) => {
      return `'${content.substring(0, 100)}...'`
    })
  }

  /**
   * Limit the number of UNION operations
   * @param {string} query - Query to process
   * @returns {string} Query with limited UNIONs
   * @private
   */
  _limitUnions (query) {
    const unionPattern = /\bUNION(\s+ALL)?\b/gi
    const matches = [...query.matchAll(unionPattern)]

    if (matches.length <= this.config.maxUnions) {
      return query
    }

    // Remove excess UNION operations
    let result = query
    for (let i = this.config.maxUnions; i < matches.length; i++) {
      result = result.replace(matches[i][0], '/* UNION removed */')
    }

    return result
  }

  /**
   * Map pattern detection severity to validator severity
   * @param {string} patternSeverity - Pattern detection severity
   * @returns {string} Validator severity
   * @private
   */
  _mapSeverity (patternSeverity) {
    const mapping = {
      [SEVERITY_LEVELS.LOW]: SEVERITY.LOW,
      [SEVERITY_LEVELS.MEDIUM]: SEVERITY.MEDIUM,
      [SEVERITY_LEVELS.HIGH]: SEVERITY.HIGH,
      [SEVERITY_LEVELS.CRITICAL]: SEVERITY.CRITICAL
    }
    return mapping[patternSeverity] || SEVERITY.MEDIUM
  }

  /**
   * Get the higher severity between two severity levels
   * @param {string} current - Current severity
   * @param {string} newSeverity - New severity to compare
   * @returns {string} Higher severity
   * @private
   */
  _getHigherSeverity (current, newSeverity) {
    if (!current) return newSeverity
    if (!newSeverity) return current

    const severityOrder = [SEVERITY.LOW, SEVERITY.MEDIUM, SEVERITY.HIGH, SEVERITY.CRITICAL]
    const currentIndex = severityOrder.indexOf(current)
    const newIndex = severityOrder.indexOf(newSeverity)

    return newIndex > currentIndex ? newSeverity : current
  }

  /**
   * Update validator configuration
   * @param {Object} newConfig - New configuration to merge
   */
  updateConfig (newConfig) {
    this.config = { ...this.config, ...newConfig }
  }

  /**
   * Get current configuration
   * @returns {Object} Current configuration
   */
  getConfig () {
    return { ...this.config }
  }

  /**
   * Safely escape SQL values using sqlstring library
   * @param {*} value - Value to escape
   * @returns {string} Escaped SQL value
   */
  escapeValue (value) {
    return sqlstring.escape(value)
  }

  /**
   * Safely escape SQL identifiers (table/column names) using sqlstring library
   * @param {string} identifier - Identifier to escape
   * @returns {string} Escaped SQL identifier
   */
  escapeIdentifier (identifier) {
    return sqlstring.escapeId(identifier)
  }

  /**
   * Format SQL query with escaped values using sqlstring library
   * @param {string} sql - SQL query with ? placeholders
   * @param {Array} values - Values to insert
   * @returns {string} Formatted SQL query
   */
  format (sql, values) {
    return sqlstring.format(sql, values)
  }
}

/**
 * Create a SQL validator with default configuration
 * @param {Object} config - Optional configuration overrides
 * @returns {SQLValidator} New validator instance
 */
function createSQLValidator (config = {}) {
  return new SQLValidator(config)
}

/**
 * Quick validation function for simple use cases
 * @param {string} query - SQL query to validate
 * @param {Object} config - Optional configuration
 * @returns {Promise<Object>} Validation result
 */
async function validateSQL (query, config = {}) {
  const validator = new SQLValidator(config)
  return await validator.validate(query)
}

/**
 * Quick sanitization function for simple use cases
 * @param {string} query - SQL query to sanitize
 * @param {Object} config - Optional configuration
 * @returns {Promise<Object>} Sanitization result
 */
async function sanitizeSQL (query, config = {}) {
  const validator = new SQLValidator(config)
  return await validator.sanitize(query)
}

module.exports = {
  SQLValidator,
  createSQLValidator,
  validateSQL,
  sanitizeSQL,
  SEVERITY,
  DEFAULT_CONFIG,
  SQL_INJECTION_PATTERNS,
  DATABASE_SPECIFIC_PATTERNS
}
