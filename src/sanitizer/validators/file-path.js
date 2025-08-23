/**
 * File Path Validator for MCP Sanitizer
 *
 * This module provides comprehensive validation and sanitization for file paths,
 * protecting against directory traversal attacks, access to restricted system
 * directories, and invalid file extensions.
 *
 * Features:
 * - Directory traversal detection and prevention
 * - System directory access restriction
 * - File extension validation
 * - Cross-platform path handling
 * - Configurable validation rules
 * - Async validation support
 *
 * @example
 * const { FilePathValidator } = require('./file-path');
 * const validator = new FilePathValidator(config);
 *
 * const result = await validator.validate('/safe/path/file.txt');
 * if (result.isValid) {
 *   console.log('Sanitized path:', result.sanitized);
 * } else {
 *   console.error('Validation failed:', result.warnings);
 * }
 */

const path = require('path')
// const { validationUtils } = require('../../utils') // Unused - commented to fix ESLint
const { detectAllPatterns, SEVERITY_LEVELS } = require('../../patterns')
const sanitizeFilename = require('sanitize-filename')
const pathIsInside = require('path-is-inside')
const { securityDecode, hasEncoding } = require('../../utils/security-decoder')

/**
 * File path validation severity levels
 */
const SEVERITY = {
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical'
}

/**
 * Default configuration for file path validation
 */
const DEFAULT_CONFIG = {
  allowedExtensions: ['.txt', '.json', '.csv', '.md', '.log'],
  blockedExtensions: ['.exe', '.bat', '.cmd', '.ps1', '.sh', '.scr'],
  allowAbsolutePaths: false,
  allowRelativePaths: true,
  maxPathLength: 260, // Windows MAX_PATH limit
  allowSystemDirectories: false,
  customDangerousPaths: [],
  normalizeBeforeValidation: true,
  strictMode: false
}

/**
 * System directories that are typically restricted
 */
const DANGEROUS_PATHS = {
  unix: [
    '/etc/',
    '/proc/',
    '/sys/',
    '/dev/',
    '/root/',
    '/boot/',
    '/var/log/',
    '/usr/bin/',
    '/usr/sbin/',
    '/sbin/',
    '/bin/'
  ],
  windows: [
    'C:\\Windows\\',
    'C:\\System32\\',
    'C:\\Program Files\\',
    'C:\\Program Files (x86)\\',
    'C:\\ProgramData\\',
    'C:\\Users\\Default\\',
    'C:\\Boot\\',
    'C:\\System Volume Information\\'
  ]
}

/**
 * File Path Validator Class
 */
class FilePathValidator {
  /**
   * Create a new file path validator
   * @param {Object} config - Validation configuration
   */
  constructor (config = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config }
    this.dangerousPaths = [
      ...DANGEROUS_PATHS.unix,
      ...DANGEROUS_PATHS.windows,
      ...this.config.customDangerousPaths
    ]
  }

  /**
   * Validate a file path
   * @param {string} filePath - The file path to validate
   * @param {Object} options - Additional validation options
   * @returns {Promise<Object>} Validation result
   */
  async validate (filePath, options = {}) {
    const result = {
      isValid: false,
      sanitized: null,
      warnings: [],
      severity: null,
      metadata: {
        originalPath: filePath,
        normalizedPath: null,
        extension: null,
        isAbsolute: false,
        detectedPatterns: [],
        wasDecoded: false,
        decodingSteps: []
      }
    }

    try {
      // Basic input validation
      if (typeof filePath !== 'string') {
        result.warnings.push('File path must be a string')
        result.severity = SEVERITY.HIGH
        return result
      }

      if (!filePath || filePath.trim().length === 0) {
        result.warnings.push('File path cannot be empty')
        result.severity = SEVERITY.HIGH
        return result
      }

      // Check path length
      if (filePath.length > this.config.maxPathLength) {
        result.warnings.push(`File path exceeds maximum length of ${this.config.maxPathLength} characters`)
        result.severity = SEVERITY.MEDIUM
        return result
      }

      // SECURITY: Decode and normalize the path first
      const decodedResult = securityDecode(filePath, {
        decodeUnicode: true,
        decodeUrl: true,
        normalizePath: true,
        stripDangerous: false // Don't strip for paths, we want to detect them
      })
      
      if (decodedResult.wasDecoded) {
        result.metadata.wasDecoded = true
        result.metadata.decodingSteps = decodedResult.decodingSteps
        result.warnings.push(`Encoded sequences detected and decoded: ${decodedResult.decodingSteps.join(', ')}`)
      }
      
      let normalizedPath = decodedResult.decoded
      
      // Normalize path if configured
      if (this.config.normalizeBeforeValidation) {
        normalizedPath = path.normalize(normalizedPath)
        result.metadata.normalizedPath = normalizedPath
      }

      // Check for security patterns
      const patternResult = detectAllPatterns(normalizedPath)
      if (patternResult.detected) {
        result.metadata.detectedPatterns = patternResult.patterns
        result.warnings.push(`Security patterns detected: ${patternResult.patterns.join(', ')}`)
        result.severity = this._mapSeverity(patternResult.severity)

        if (patternResult.severity === SEVERITY_LEVELS.CRITICAL) {
          return result
        }
      }

      // Check for directory traversal
      const traversalResult = this._checkDirectoryTraversal(normalizedPath)
      if (!traversalResult.isValid) {
        result.warnings.push(...traversalResult.warnings)
        result.severity = this._getHigherSeverity(result.severity, SEVERITY.CRITICAL)
        return result
      }

      // Check absolute/relative path restrictions
      const isAbsolute = path.isAbsolute(normalizedPath)
      result.metadata.isAbsolute = isAbsolute

      if (isAbsolute && !this.config.allowAbsolutePaths) {
        result.warnings.push('Absolute paths are not allowed')
        result.severity = this._getHigherSeverity(result.severity, SEVERITY.HIGH)
        return result
      }

      if (!isAbsolute && !this.config.allowRelativePaths) {
        result.warnings.push('Relative paths are not allowed')
        result.severity = this._getHigherSeverity(result.severity, SEVERITY.HIGH)
        return result
      }

      // Check for access to dangerous system directories
      const systemDirResult = this._checkSystemDirectories(normalizedPath)
      if (!systemDirResult.isValid) {
        result.warnings.push(...systemDirResult.warnings)
        result.severity = this._getHigherSeverity(result.severity, SEVERITY.CRITICAL)
        return result
      }

      // Check file extension
      const extension = path.extname(normalizedPath).toLowerCase()
      result.metadata.extension = extension

      const extensionResult = this._checkFileExtension(extension)
      if (!extensionResult.isValid) {
        result.warnings.push(...extensionResult.warnings)
        result.severity = this._getHigherSeverity(result.severity, extensionResult.severity)

        if (extensionResult.severity === SEVERITY.CRITICAL) {
          return result
        }
      }

      // If we get here, the path is valid
      result.isValid = true
      result.sanitized = normalizedPath

      // Set severity to lowest if there were warnings but path is still valid
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
   * Sanitize a file path
   * @param {string} filePath - The file path to sanitize
   * @param {Object} options - Sanitization options
   * @returns {Promise<Object>} Sanitization result
   */
  async sanitize (filePath, options = {}) {
    const validationResult = await this.validate(filePath, options)

    if (validationResult.isValid) {
      return validationResult
    }

    // Attempt to sanitize the path
    let sanitized = filePath
    const warnings = [...validationResult.warnings]

    try {
      // Remove dangerous characters
      sanitized = sanitized.replace(/[<>:"|?*]/g, '')

      // Handle directory traversal by removing ../ patterns
      sanitized = sanitized.replace(/\.\./g, '')

      // Normalize path separators
      sanitized = sanitized.replace(/[/\\]+/g, path.sep)

      // Remove leading/trailing whitespace
      sanitized = sanitized.trim()

      // If path becomes empty after sanitization, use a safe default
      if (!sanitized) {
        sanitized = 'sanitized_file.txt'
        warnings.push('Path was empty after sanitization, using default filename')
      }

      // Re-validate the sanitized path
      const revalidationResult = await this.validate(sanitized, options)

      return {
        isValid: revalidationResult.isValid,
        sanitized: revalidationResult.isValid ? revalidationResult.sanitized : null,
        warnings: [...warnings, ...revalidationResult.warnings],
        severity: this._getHigherSeverity(validationResult.severity, revalidationResult.severity),
        metadata: {
          ...validationResult.metadata,
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
   * Check for directory traversal attacks
   * @param {string} filePath - The file path to check
   * @returns {Object} Check result
   * @private
   */
  _checkDirectoryTraversal (filePath) {
    const result = {
      isValid: true,
      warnings: []
    }

    // SECURITY: First check if it's an absolute path (common bypass)
    if (path.isAbsolute(filePath)) {
      // Check if it's trying to access system directories
      const lowerPath = filePath.toLowerCase()
      const systemPaths = [
        '/etc/', '/proc/', '/sys/', '/dev/', '/root/', '/boot/',
        '/var/log/', '/usr/bin/', '/usr/sbin/', '/sbin/', '/bin/',
        'c:\\windows\\', 'c:\\system32\\', 'c:\\program files\\'
      ]
      
      for (const sysPath of systemPaths) {
        if (lowerPath.startsWith(sysPath)) {
          result.isValid = false
          result.warnings.push(`Absolute path to system directory detected: ${sysPath}`)
          return result
        }
      }
    }

    // Check for various directory traversal patterns
    // Note: These should already be decoded by securityDecode
    const traversalPatterns = [
      /\.\./, // Standard directory traversal
      /\.{2,}/, // Multiple dots
      /%2e%2e/i, // URL encoded .. (should be decoded)
      /%252e%252e/i, // Double URL encoded .. (should be decoded)
      /\.%2e/i, // Mixed encoding (should be decoded)
      /%2e\./i, // Mixed encoding (should be decoded)
      /\.\\/i, // Windows traversal with backslash
      /\\\./, // Windows traversal
      /\.\/%2e%2e/i // Mixed path separators (should be decoded)
    ]

    for (const pattern of traversalPatterns) {
      if (pattern.test(filePath)) {
        result.isValid = false
        result.warnings.push(`Directory traversal pattern detected: ${pattern.source}`)
      }
    }

    // Additional check for normalized path containing ..
    if (filePath.includes('..')) {
      result.isValid = false
      result.warnings.push('Directory traversal detected in normalized path')
    }

    // Check for UNC paths (Windows network paths)
    if (/^\\\\/.test(filePath)) {
      result.isValid = false
      result.warnings.push('UNC path detected - network paths not allowed')
    }

    return result
  }

  /**
   * Check for access to system directories
   * @param {string} filePath - The file path to check
   * @returns {Object} Check result
   * @private
   */
  _checkSystemDirectories (filePath) {
    const result = {
      isValid: true,
      warnings: []
    }

    if (this.config.allowSystemDirectories) {
      return result
    }

    const lowerPath = filePath.toLowerCase()

    for (const dangerousPath of this.dangerousPaths) {
      const lowerDangerousPath = dangerousPath.toLowerCase()

      if (lowerPath.startsWith(lowerDangerousPath)) {
        result.isValid = false
        result.warnings.push(`Access to system directory not allowed: ${dangerousPath}`)
      }
    }

    return result
  }

  /**
   * Check file extension against allowed/blocked lists
   * @param {string} extension - The file extension to check
   * @returns {Object} Check result
   * @private
   */
  _checkFileExtension (extension) {
    const result = {
      isValid: true,
      warnings: [],
      severity: null
    }

    if (!extension) {
      return result // No extension is generally allowed
    }

    // Check blocked extensions first (higher priority)
    if (this.config.blockedExtensions.includes(extension)) {
      result.isValid = false
      result.warnings.push(`File extension ${extension} is blocked for security reasons`)
      result.severity = SEVERITY.CRITICAL
      return result
    }

    // Check allowed extensions if specified
    if (this.config.allowedExtensions && this.config.allowedExtensions.length > 0) {
      if (!this.config.allowedExtensions.includes(extension)) {
        result.isValid = false
        result.warnings.push(`File extension ${extension} is not in the allowed list: ${this.config.allowedExtensions.join(', ')}`)
        result.severity = SEVERITY.MEDIUM
      }
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
    this.dangerousPaths = [
      ...DANGEROUS_PATHS.unix,
      ...DANGEROUS_PATHS.windows,
      ...this.config.customDangerousPaths
    ]
  }

  /**
   * Get current configuration
   * @returns {Object} Current configuration
   */
  getConfig () {
    return { ...this.config }
  }

  /**
   * Sanitize a filename using sanitize-filename library
   * @param {string} filename - Filename to sanitize
   * @param {Object} options - Sanitization options
   * @returns {string} Sanitized filename
   */
  sanitizeFilename (filename, options = {}) {
    const defaultOptions = {
      replacement: '_'
    }
    return sanitizeFilename(filename, { ...defaultOptions, ...options })
  }

  /**
   * Check if a path is inside another path using path-is-inside
   * @param {string} childPath - Path to check
   * @param {string} parentPath - Parent path
   * @returns {boolean} True if childPath is inside parentPath
   */
  isPathInside (childPath, parentPath) {
    try {
      // Resolve paths to handle relative paths
      const resolvedChild = path.resolve(childPath)
      const resolvedParent = path.resolve(parentPath)
      return pathIsInside(resolvedChild, resolvedParent)
    } catch (error) {
      // If paths cannot be resolved, consider it unsafe
      return false
    }
  }

  /**
   * Check if a path is safe within allowed base paths
   * @param {string} filePath - Path to check
   * @param {string[]} allowedPaths - Array of allowed base paths
   * @returns {boolean} True if path is within any allowed path
   */
  isPathSafe (filePath, allowedPaths = []) {
    if (!allowedPaths.length) {
      // If no allowed paths specified, check if it's not in dangerous paths
      return !this._isInDangerousPaths(filePath)
    }

    // Check if path is inside any allowed path
    return allowedPaths.some(allowedPath => {
      return this.isPathInside(filePath, allowedPath)
    })
  }

  /**
   * Extract and sanitize just the filename from a path
   * @param {string} filePath - Full file path
   * @returns {string} Sanitized filename
   */
  extractSafeFilename (filePath) {
    const filename = path.basename(filePath)
    return this.sanitizeFilename(filename)
  }
}

/**
 * Create a file path validator with default configuration
 * @param {Object} config - Optional configuration overrides
 * @returns {FilePathValidator} New validator instance
 */
function createFilePathValidator (config = {}) {
  return new FilePathValidator(config)
}

/**
 * Quick validation function for simple use cases
 * @param {string} filePath - File path to validate
 * @param {Object} config - Optional configuration
 * @returns {Promise<Object>} Validation result
 */
async function validateFilePath (filePath, config = {}) {
  const validator = new FilePathValidator(config)
  return await validator.validate(filePath)
}

/**
 * Quick sanitization function for simple use cases
 * @param {string} filePath - File path to sanitize
 * @param {Object} config - Optional configuration
 * @returns {Promise<Object>} Sanitization result
 */
async function sanitizeFilePath (filePath, config = {}) {
  const validator = new FilePathValidator(config)
  return await validator.sanitize(filePath)
}

module.exports = {
  FilePathValidator,
  createFilePathValidator,
  validateFilePath,
  sanitizeFilePath,
  SEVERITY,
  DEFAULT_CONFIG,
  DANGEROUS_PATHS
}
