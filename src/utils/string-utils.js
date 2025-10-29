/**
 * String manipulation and validation utilities for MCP Sanitizer
 *
 * This module provides reusable functions for string sanitization,
 * validation, and manipulation used throughout the MCP Sanitizer.
 */

const escapeHtml = require('escape-html');

/**
 * HTML encode a string to prevent XSS attacks
 * @param {string} str - The string to encode
 * @returns {string} - HTML encoded string
 * @throws {Error} - If input is not a string
 */
function htmlEncode (str) {
  if (typeof str !== 'string') {
    throw new Error('Input must be a string');
  }

  // Use escape-html library for better security and performance
  return escapeHtml(str);
}

/**
 * Check if a string exceeds the maximum allowed length
 * @param {string} str - The string to check
 * @param {number} maxLength - Maximum allowed length
 * @returns {boolean} - True if string is within length limit
 * @throws {Error} - If parameters are invalid
 */
function isWithinLengthLimit (str, maxLength) {
  if (typeof str !== 'string') {
    throw new Error('String parameter must be a string');
  }

  if (typeof maxLength !== 'number' || maxLength < 0) {
    throw new Error('Max length must be a non-negative number');
  }

  return str.length <= maxLength;
}

/**
 * Validate string length and throw error if exceeded
 * @param {string} str - The string to validate
 * @param {number} maxLength - Maximum allowed length
 * @throws {Error} - If string exceeds maximum length
 */
function validateStringLength (str, maxLength) {
  if (!isWithinLengthLimit(str, maxLength)) {
    throw new Error(`String exceeds maximum length of ${maxLength} characters`);
  }
}

/**
 * Check if a string contains any blocked patterns
 * @param {string} str - The string to check
 * @param {RegExp[]} patterns - Array of regex patterns to check against
 * @returns {RegExp|null} - The first matching pattern or null if none match
 * @throws {Error} - If parameters are invalid
 */
function findBlockedPattern (str, patterns) {
  if (typeof str !== 'string') {
    throw new Error('String parameter must be a string');
  }

  if (!Array.isArray(patterns)) {
    throw new Error('Patterns must be an array');
  }

  for (const pattern of patterns) {
    if (!(pattern instanceof RegExp)) {
      throw new Error('All patterns must be RegExp objects');
    }

    if (pattern.test(str)) {
      return pattern;
    }
  }

  return null;
}

/**
 * Validate string against blocked patterns
 * @param {string} str - The string to validate
 * @param {RegExp[]} patterns - Array of regex patterns to check against
 * @throws {Error} - If string contains blocked patterns
 */
function validateAgainstBlockedPatterns (str, patterns, context = {}) {
  const matchedPattern = findBlockedPattern(str, patterns);
  if (matchedPattern) {
    // For SQL context with PostgreSQL dollar quotes, provide specific message
    if (context.type === 'sql' && str.includes('$$')) {
      // Check if it's actually PostgreSQL dollar quoting
      const dollarQuotePattern = /\$\$.*?\$\$/;
      if (dollarQuotePattern.test(str)) {
        throw new Error('PostgreSQL dollar quoting detected');
      }
    }
    throw new Error(`String contains blocked pattern: ${matchedPattern}`);
  }
}

/**
 * Check if string contains SQL injection keywords
 * @param {string} str - The string to check
 * @param {string[]} keywords - Array of SQL keywords to check against
 * @returns {string|null} - The first matching keyword or null if none match
 * @throws {Error} - If parameters are invalid
 */
function findSQLKeyword (str, keywords) {
  if (typeof str !== 'string') {
    throw new Error('String parameter must be a string');
  }

  if (!Array.isArray(keywords)) {
    throw new Error('Keywords must be an array');
  }

  const upperStr = str.toUpperCase();

  for (const keyword of keywords) {
    if (typeof keyword !== 'string') {
      throw new Error('All keywords must be strings');
    }

    // Handle pattern keywords like 'SELECT.*FROM'
    if (keyword.includes('.*')) {
      const pattern = new RegExp(keyword, 'i');
      if (pattern.test(str)) {
        return keyword;
      }
    } else {
      // Simple keyword matching
      if (upperStr.includes(keyword.toUpperCase())) {
        return keyword;
      }
    }
  }

  return null;
}

/**
 * Validate string against SQL injection keywords
 * @param {string} str - The string to validate
 * @param {string[]} keywords - Array of SQL keywords to check against
 * @throws {Error} - If string contains SQL keywords
 */
function validateAgainstSQLKeywords (str, keywords) {
  const matchedKeyword = findSQLKeyword(str, keywords);
  if (matchedKeyword) {
    throw new Error(`String contains potentially dangerous SQL keyword: ${matchedKeyword}`);
  }
}

/**
 * Safely trim a string, handling edge cases
 * @param {*} input - The input to trim (will be converted to string if possible)
 * @returns {string} - Trimmed string
 * @throws {Error} - If input cannot be converted to string
 */
function safeTrim (input) {
  if (input === null || input === undefined) {
    return '';
  }

  if (typeof input !== 'string') {
    if (typeof input.toString === 'function') {
      input = input.toString();
    } else {
      throw new Error('Input cannot be converted to string');
    }
  }

  return input.trim();
}

/**
 * Check if a string is empty or contains only whitespace
 * @param {string} str - The string to check
 * @returns {boolean} - True if string is empty or whitespace only
 */
function isEmpty (str) {
  if (typeof str !== 'string') {
    return false;
  }

  return str.trim().length === 0;
}

/**
 * Normalize line endings in a string to LF (\n)
 * @param {string} str - The string to normalize
 * @returns {string} - String with normalized line endings
 * @throws {Error} - If input is not a string
 */
function normalizeLineEndings (str) {
  if (typeof str !== 'string') {
    throw new Error('Input must be a string');
  }

  return str.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
}

/**
 * Escape special regex characters in a string
 * @param {string} str - The string to escape
 * @returns {string} - String with escaped regex characters
 * @throws {Error} - If input is not a string
 */
function escapeRegex (str) {
  if (typeof str !== 'string') {
    throw new Error('Input must be a string');
  }

  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Check if a string contains only safe characters (alphanumeric, spaces, common punctuation)
 * @param {string} str - The string to check
 * @param {RegExp} [allowedCharsPattern] - Custom pattern for allowed characters
 * @returns {boolean} - True if string contains only safe characters
 * @throws {Error} - If input is not a string
 */
function containsOnlySafeChars (str, allowedCharsPattern = /^[a-zA-Z0-9\s\-_.,!?()[\]{}:;"'@#$%^&*+=~`|\\/<>]*$/) {
  if (typeof str !== 'string') {
    throw new Error('Input must be a string');
  }

  if (!(allowedCharsPattern instanceof RegExp)) {
    throw new Error('Allowed characters pattern must be a RegExp');
  }

  return allowedCharsPattern.test(str);
}

// Import security enhancements
const {
  detectDirectionalOverrides,
  detectNullBytes,
  handleEmptyStrings
} = require('./security-enhancements');

/**
 * Enhanced string validation with security enhancements
 * @param {string} str - String to validate
 * @param {Object} options - Validation options
 * @returns {Object} Enhanced validation result
 */
function enhancedStringValidation (str, options = {}) {
  const {
    checkDirectionalOverrides = true,
    checkNullBytes = true,
    // checkMultipleEncoding = false, // Only for URLs - Unused
    handleEmpty = true,
    emptyContext = {}
  } = options;

  const results = {
    isValid: true,
    warnings: [],
    sanitized: str,
    metadata: {}
  };

  // Check for directional overrides
  if (checkDirectionalOverrides) {
    const dirResult = detectDirectionalOverrides(str);
    if (dirResult.detected) {
      results.warnings.push(...dirResult.warnings);
      results.sanitized = dirResult.sanitized;
      results.metadata.directionalOverrides = dirResult.metadata;
    }
  }

  // Check for null bytes
  if (checkNullBytes) {
    const nullResult = detectNullBytes(results.sanitized);
    if (nullResult.detected) {
      results.warnings.push(...nullResult.warnings);
      results.sanitized = nullResult.sanitized;
      results.metadata.nullBytes = nullResult.metadata;
    }
  }

  // Handle empty strings
  if (handleEmpty) {
    const emptyResult = handleEmptyStrings(results.sanitized, emptyContext);
    if (!emptyResult.isValid) {
      results.isValid = false;
      results.warnings.push(...emptyResult.warnings);
    }
    if (emptyResult.processed !== results.sanitized) {
      results.sanitized = emptyResult.processed;
    }
    results.metadata.emptyString = emptyResult.metadata;
  }

  return results;
}

module.exports = {
  htmlEncode,
  isWithinLengthLimit,
  validateStringLength,
  findBlockedPattern,
  validateAgainstBlockedPatterns,
  findSQLKeyword,
  validateAgainstSQLKeywords,
  safeTrim,
  isEmpty,
  normalizeLineEndings,
  escapeRegex,
  containsOnlySafeChars,
  enhancedStringValidation
};
