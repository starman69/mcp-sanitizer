/**
 * Common validation functions for MCP Sanitizer
 *
 * This module provides reusable validation functions that are
 * used across different validators and sanitizers.
 */

const path = require('path')
const { URL } = require('url')

/**
 * Validate that a value is a non-empty string
 * @param {*} value - The value to validate
 * @param {string} [paramName='value'] - Parameter name for error messages
 * @throws {Error} - If value is not a non-empty string
 */
function validateNonEmptyString (value, paramName = 'value') {
  if (typeof value !== 'string') {
    throw new Error(`${paramName} must be a string`)
  }

  if (value.trim().length === 0) {
    throw new Error(`${paramName} cannot be empty`)
  }
}

/**
 * Validate that a value is a positive number
 * @param {*} value - The value to validate
 * @param {string} [paramName='value'] - Parameter name for error messages
 * @throws {Error} - If value is not a positive number
 */
function validatePositiveNumber (value, paramName = 'value') {
  if (typeof value !== 'number') {
    throw new Error(`${paramName} must be a number`)
  }

  if (!isFinite(value)) {
    throw new Error(`${paramName} must be a finite number`)
  }

  if (value < 0) {
    throw new Error(`${paramName} must be a positive number`)
  }
}

/**
 * Validate that a value is an array
 * @param {*} value - The value to validate
 * @param {string} [paramName='value'] - Parameter name for error messages
 * @throws {Error} - If value is not an array
 */
function validateArray (value, paramName = 'value') {
  if (!Array.isArray(value)) {
    throw new Error(`${paramName} must be an array`)
  }
}

/**
 * Validate that a value is a function
 * @param {*} value - The value to validate
 * @param {string} [paramName='value'] - Parameter name for error messages
 * @throws {Error} - If value is not a function
 */
function validateFunction (value, paramName = 'value') {
  if (typeof value !== 'function') {
    throw new Error(`${paramName} must be a function`)
  }
}

/**
 * Validate that a value is a RegExp
 * @param {*} value - The value to validate
 * @param {string} [paramName='value'] - Parameter name for error messages
 * @throws {Error} - If value is not a RegExp
 */
function validateRegExp (value, paramName = 'value') {
  if (!(value instanceof RegExp)) {
    throw new Error(`${paramName} must be a RegExp`)
  }
}

/**
 * Validate file path for security issues
 * @param {string} filePath - The file path to validate
 * @returns {string} - Normalized file path
 * @throws {Error} - If file path is unsafe
 */
function validateFilePath (filePath) {
  validateNonEmptyString(filePath, 'filePath')

  // Normalize the path for security checks
  const normalizedPath = path.normalize(filePath)

  // Check for directory traversal attempts
  if (normalizedPath.includes('..')) {
    throw new Error('Directory traversal detected in file path')
  }

  // Check for access to system directories (Unix/Linux)
  const dangerousUnixPaths = ['/etc/', '/proc/', '/sys/', '/dev/', '/root/']
  const dangerousWindowsPaths = ['C:\\Windows\\', 'C:\\System32\\', 'C:\\Program Files\\']

  const lowerPath = normalizedPath.toLowerCase()

  for (const dangerousPath of [...dangerousUnixPaths, ...dangerousWindowsPaths]) {
    if (lowerPath.startsWith(dangerousPath.toLowerCase())) {
      throw new Error(`Access to system directory not allowed: ${dangerousPath}`)
    }
  }

  // Return original path if safe, not normalized
  return filePath
}

/**
 * Validate file extension against allowed list
 * @param {string} filePath - The file path to validate
 * @param {string[]} allowedExtensions - Array of allowed file extensions
 * @throws {Error} - If file extension is not allowed
 */
function validateFileExtension (filePath, allowedExtensions) {
  validateNonEmptyString(filePath, 'filePath')
  validateArray(allowedExtensions, 'allowedExtensions')

  const ext = path.extname(filePath).toLowerCase()

  if (ext && !allowedExtensions.includes(ext)) {
    throw new Error(`File extension ${ext} not allowed. Allowed extensions: ${allowedExtensions.join(', ')}`)
  }
}

/**
 * Validate URL for security issues
 * @param {string} url - The URL to validate
 * @param {string[]} [allowedProtocols=['http', 'https']] - Array of allowed protocols
 * @returns {URL} - Parsed URL object
 * @throws {Error} - If URL is unsafe
 */
function validateURL (url, allowedProtocols = ['http', 'https']) {
  validateNonEmptyString(url, 'url')
  validateArray(allowedProtocols, 'allowedProtocols')

  let parsedUrl

  try {
    parsedUrl = new URL(url)
  } catch (error) {
    throw new Error('Invalid URL format')
  }

  // Check protocol
  const protocol = parsedUrl.protocol.slice(0, -1) // Remove trailing colon
  if (!allowedProtocols.includes(protocol)) {
    throw new Error(`Protocol ${protocol} not allowed. Allowed protocols: ${allowedProtocols.join(', ')}`)
  }

  // Check for suspicious patterns in URL path
  if (parsedUrl.pathname.includes('..')) {
    throw new Error('Directory traversal detected in URL path')
  }

  return parsedUrl
}

/**
 * Validate URL against restricted locations (localhost, private IPs, etc.)
 * @param {string|URL} url - The URL to validate (string or URL object)
 * @throws {Error} - If URL points to restricted location
 */
function validateURLLocation (url) {
  let parsedUrl = url

  if (typeof url === 'string') {
    parsedUrl = new URL(url)
  } else if (!(url instanceof URL)) {
    throw new Error('URL must be a string or URL object')
  }

  const hostname = parsedUrl.hostname.toLowerCase()

  // Check for localhost - allow localhost with explicit port for development
  if ((hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1') && !parsedUrl.port) {
    throw new Error('URL points to localhost without explicit port')
  }

  // Check for private IP ranges
  const privateIPPatterns = [
    /^127\./, // 127.0.0.0/8 (loopback)
    /^10\./, // 10.0.0.0/8 (private)
    /^192\.168\./, // 192.168.0.0/16 (private)
    /^172\.(1[6-9]|2[0-9]|3[01])\./ // 172.16.0.0/12 (private)
  ]

  for (const pattern of privateIPPatterns) {
    if (pattern.test(hostname)) {
      throw new Error(`URL points to private IP range: ${hostname}`)
    }
  }

  // Check for link-local addresses
  if (hostname.startsWith('169.254.') || hostname.startsWith('fe80:')) {
    throw new Error(`URL points to link-local address: ${hostname}`)
  }
}

/**
 * Validate command string for injection patterns
 * @param {string} command - The command string to validate
 * @returns {string} - Trimmed command string
 * @throws {Error} - If command contains dangerous patterns
 */
function validateCommand (command) {
  validateNonEmptyString(command, 'command')

  // Check for command injection patterns - based on original logic
  const dangerousPatterns = [
    /[;&|`$(){}[\]]/, // Shell metacharacters
    /(^|\s+)(rm|del|format|mkfs[\w.]*|dd)\s+/i, // Dangerous commands
    />\s*\/dev\/|<\s*\/dev\//, // Device redirection
    /\|\s*nc\s+|\|\s*netcat\s+/i // Network tools
  ]

  for (const pattern of dangerousPatterns) {
    if (pattern.test(command)) {
      throw new Error('Command contains dangerous patterns')
    }
  }

  return command.trim()
}

/**
 * Validate options object structure
 * @param {object} options - Options object to validate
 * @param {object} schema - Schema defining expected structure
 * @throws {Error} - If options don't match schema
 */
function validateOptions (options, schema) {
  if (typeof options !== 'object' || options === null) {
    throw new Error('Options must be an object')
  }

  if (typeof schema !== 'object' || schema === null) {
    throw new Error('Schema must be an object')
  }

  for (const [key, validator] of Object.entries(schema)) {
    if (key in options) {
      try {
        validator(options[key], key)
      } catch (error) {
        throw new Error(`Invalid option '${key}': ${error.message}`)
      }
    }
  }
}

/**
 * Validate that a value is within a specified range
 * @param {number} value - The value to validate
 * @param {number} min - Minimum allowed value (inclusive)
 * @param {number} max - Maximum allowed value (inclusive)
 * @param {string} [paramName='value'] - Parameter name for error messages
 * @throws {Error} - If value is outside the range
 */
function validateRange (value, min, max, paramName = 'value') {
  validatePositiveNumber(value, paramName)
  validatePositiveNumber(min, 'min')
  validatePositiveNumber(max, 'max')

  if (min > max) {
    throw new Error('Minimum value cannot be greater than maximum value')
  }

  if (value < min || value > max) {
    throw new Error(`${paramName} must be between ${min} and ${max} (inclusive)`)
  }
}

/**
 * Validate that an array contains only specific types
 * @param {Array} array - The array to validate
 * @param {string} expectedType - Expected type of array elements
 * @param {string} [paramName='array'] - Parameter name for error messages
 * @throws {Error} - If array contains elements of wrong type
 */
function validateArrayOfType (array, expectedType, paramName = 'array') {
  validateArray(array, paramName)

  for (let i = 0; i < array.length; i++) {
    const element = array[i]
    let actualType = typeof element

    // Special handling for RegExp objects
    if (expectedType === 'regexp' && element instanceof RegExp) {
      actualType = 'regexp'
    }

    if (actualType !== expectedType) {
      throw new Error(`${paramName}[${i}] must be of type ${expectedType}, got ${actualType}`)
    }
  }
}

/**
 * Create a validator function that checks multiple conditions
 * @param {...Function} validators - Validator functions to combine
 * @returns {Function} - Combined validator function
 */
function combineValidators (...validators) {
  return function (value, paramName) {
    for (const validator of validators) {
      validator(value, paramName)
    }
  }
}

module.exports = {
  validateNonEmptyString,
  validatePositiveNumber,
  validateArray,
  validateFunction,
  validateRegExp,
  validateFilePath,
  validateFileExtension,
  validateURL,
  validateURLLocation,
  validateCommand,
  validateOptions,
  validateRange,
  validateArrayOfType,
  combineValidators
}
