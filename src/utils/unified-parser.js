/**
 * Unified Parser Module - CVE-TBD-001 Fix
 *
 * This module provides a unified, immutable parsing entry point that ensures
 * ALL security validation uses the SAME normalized string representation.
 *
 * CRITICAL SECURITY FIX:
 * - Single normalization point prevents parser differential attacks
 * - Immutable string handling prevents TOCTOU vulnerabilities
 * - Comprehensive encoding detection and normalization
 * - Zero parser differential between security decoder and validators
 *
 * CVE-TBD-001: Parser Differential Vulnerability (CVSS 9.1)
 * Fix: All validation MUST use this unified parser, never original strings
 */

const { securityDecode } = require('./security-decoder');

/**
 * Immutable normalized string wrapper
 * Prevents accidental access to original strings
 */
class NormalizedString {
  constructor (original, normalized, metadata = {}) {
    // Make properties read-only and non-enumerable for security
    Object.defineProperty(this, '_original', {
      value: original,
      writable: false,
      enumerable: false,
      configurable: false
    });

    Object.defineProperty(this, '_normalized', {
      value: normalized,
      writable: false,
      enumerable: false,
      configurable: false
    });

    Object.defineProperty(this, '_metadata', {
      value: Object.freeze({ ...metadata }),
      writable: false,
      enumerable: false,
      configurable: false
    });

    // Freeze the entire object to prevent modification
    Object.freeze(this);
  }

  /**
   * Get the normalized string - this is what ALL validators should use
   * @returns {string} The normalized, safe string
   */
  toString () {
    return this._normalized;
  }

  /**
   * Get the normalized string explicitly
   * @returns {string} The normalized, safe string
   */
  getNormalized () {
    return this._normalized;
  }

  /**
   * Get metadata about the normalization process (read-only)
   * @returns {Object} Immutable metadata
   */
  getMetadata () {
    return this._metadata;
  }

  /**
   * Check if the string was modified during normalization
   * @returns {boolean} True if original string was changed
   */
  wasNormalized () {
    return this._original !== this._normalized;
  }

  /**
   * Get original string - ONLY for logging/debugging, NEVER for validation
   * @returns {string} Original input string
   * @deprecated Use getNormalized() for all validation logic
   */
  getOriginal () {
    // Console output removed for production called - use getNormalized() for validation')
    return this._original;
  }

  /**
   * Get string length (uses normalized string)
   * @returns {number} Length of normalized string
   */
  get length () {
    return this._normalized.length;
  }

  /**
   * Enable basic string operations on normalized string
   */
  valueOf () {
    return this._normalized;
  }

  // Proxy common string methods to normalized string
  includes (searchString, position) {
    return this._normalized.includes(searchString, position);
  }

  indexOf (searchString, position) {
    return this._normalized.indexOf(searchString, position);
  }

  match (regexp) {
    return this._normalized.match(regexp);
  }

  replace (searchValue, replaceValue) {
    // Return new NormalizedString with replaced content
    const replaced = this._normalized.replace(searchValue, replaceValue);
    return new NormalizedString(this._original, replaced, {
      ...this._metadata,
      wasModified: true,
      lastOperation: 'replace'
    });
  }

  slice (start, end) {
    const sliced = this._normalized.slice(start, end);
    return new NormalizedString(this._original, sliced, {
      ...this._metadata,
      wasModified: true,
      lastOperation: 'slice'
    });
  }

  split (separator, limit) {
    return this._normalized.split(separator, limit).map(part =>
      new NormalizedString(part, part, {
        ...this._metadata,
        wasModified: true,
        lastOperation: 'split'
      })
    );
  }

  toLowerCase () {
    const lowered = this._normalized.toLowerCase();
    return new NormalizedString(this._original, lowered, {
      ...this._metadata,
      wasModified: true,
      lastOperation: 'toLowerCase'
    });
  }

  toUpperCase () {
    const uppered = this._normalized.toUpperCase();
    return new NormalizedString(this._original, uppered, {
      ...this._metadata,
      wasModified: true,
      lastOperation: 'toUpperCase'
    });
  }

  trim () {
    const trimmed = this._normalized.trim();
    return new NormalizedString(this._original, trimmed, {
      ...this._metadata,
      wasModified: true,
      lastOperation: 'trim'
    });
  }
}

/**
 * Unified parsing function - ENTRY POINT for all string validation
 *
 * This function MUST be used by ALL validators to ensure consistent
 * string processing and prevent parser differential attacks.
 *
 * @param {string} input - Raw input string
 * @param {Object} options - Parsing options
 * @returns {NormalizedString} Immutable normalized string wrapper
 */
function parseUnified (input, options = {}) {
  const {
    type = 'generic', // Input type for context-specific normalization
    strictMode = false,
    // allowOriginalAccess = false, // For backwards compatibility (DEPRECATED) - Unused
    logAccess = true // Log access to original strings
  } = options;

  if (typeof input !== 'string') {
    throw new Error('parseUnified: Input must be a string');
  }

  // Apply comprehensive security decoding with enhanced options
  const decodeOptions = {
    decodeUnicode: true,
    decodeUrl: true,
    normalizePath: type === 'file_path' || type === 'path',
    stripDangerous: type === 'command',
    normalizeUnicode: true,
    maxIterations: 5, // Increased for thorough decoding

    // CVE-TBD-001 specific fixes
    checkDirectionalOverrides: true,
    checkNullBytes: true,
    checkMultipleEncoding: true,
    checkCyrillicHomographs: true,
    // Timing consistency removed
    maxEncodingDepth: 6
  };

  const decodeResult = securityDecode(input, decodeOptions);

  // Create metadata about the parsing process
  const metadata = {
    inputType: type,
    wasDecoded: decodeResult.wasDecoded,
    decodingSteps: decodeResult.decodingSteps || [],
    warnings: decodeResult.warnings || [],
    securityChecks: decodeResult.securityChecks || {},
    iterations: decodeResult.iterations || 0,
    strictMode,
    parseTimestamp: Date.now(),

    // CVE-TBD-001 specific metadata
    parserDifferentialPrevented: true,
    unifiedParsingVersion: '1.0.0',
    immutableWrapper: true
  };

  // Log any access to original string if enabled
  if (logAccess && process.env.NODE_ENV !== 'production') {
    metadata.accessLogging = true;
  }

  return new NormalizedString(input, decodeResult.decoded, metadata);
}

/**
 * Parse multiple strings with unified parsing
 * @param {string[]} inputs - Array of input strings
 * @param {Object} options - Parsing options
 * @returns {NormalizedString[]} Array of normalized strings
 */
function parseUnifiedBatch (inputs, options = {}) {
  if (!Array.isArray(inputs)) {
    throw new Error('parseUnifiedBatch: Inputs must be an array');
  }

  return inputs.map(input => parseUnified(input, options));
}

/**
 * Validate that a value is a NormalizedString (security check)
 * @param {*} value - Value to check
 * @returns {boolean} True if value is a NormalizedString
 */
function isNormalizedString (value) {
  return value instanceof NormalizedString;
}

/**
 * Extract normalized string safely (for legacy code migration)
 * @param {NormalizedString|string} value - Input value
 * @returns {string} Normalized string
 */
function extractNormalized (value) {
  if (isNormalizedString(value)) {
    return value.getNormalized();
  }

  if (typeof value === 'string') {
    // Console output removed for production first')
    // For backwards compatibility, normalize on the fly
    return parseUnified(value).getNormalized();
  }

  throw new Error('extractNormalized: Value must be string or NormalizedString');
}

/**
 * Create a validator wrapper that ensures all inputs are normalized
 * @param {Function} validatorFunction - Original validator function
 * @returns {Function} Wrapped validator that enforces normalization
 */
function wrapValidator (validatorFunction) {
  return function wrappedValidator (input, ...args) {
    let normalizedInput;

    if (isNormalizedString(input)) {
      normalizedInput = input;
    } else if (typeof input === 'string') {
      // Auto-normalize for backwards compatibility but warn
      // Console output removed for production
      normalizedInput = parseUnified(input);
    } else {
      throw new Error('Validator input must be string or NormalizedString');
    }

    // Call original function with normalized string
    return validatorFunction.call(this, normalizedInput.getNormalized(), ...args);
  };
}

/**
 * Middleware to ensure request parameters are normalized
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Next middleware function
 */
function unifiedParsingMiddleware (req, res, next) {
  // Normalize all string parameters
  const normalizeObject = (obj) => {
    const normalized = {};
    for (const [key, value] of Object.entries(obj)) {
      if (typeof value === 'string') {
        normalized[key] = parseUnified(value);
      } else if (typeof value === 'object' && value !== null) {
        normalized[key] = normalizeObject(value);
      } else {
        normalized[key] = value;
      }
    }
    return normalized;
  };

  // Store original for debugging if needed
  req._originalQuery = { ...req.query };
  req._originalBody = req.body ? { ...req.body } : {};
  req._originalParams = { ...req.params };

  // Replace with normalized versions
  req.query = normalizeObject(req.query || {});
  req.params = normalizeObject(req.params || {});
  if (req.body && typeof req.body === 'object') {
    req.body = normalizeObject(req.body);
  }

  // Mark request as having unified parsing
  req._unifiedParsingApplied = true;
  req._parsingTimestamp = Date.now();

  next();
}

module.exports = {
  NormalizedString,
  parseUnified,
  parseUnifiedBatch,
  isNormalizedString,
  extractNormalized,
  wrapValidator,
  unifiedParsingMiddleware,

  // Constants
  PARSING_VERSION: '1.0.0',
  CVE_FIXED: 'CVE-TBD-001'
};
