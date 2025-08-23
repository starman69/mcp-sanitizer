/**
 * Security Decoder Module for MCP Sanitizer
 *
 * This module provides comprehensive decoding and normalization functions
 * to prevent encoding-based bypass attacks. It implements defense-in-depth
 * by handling multiple encoding layers and normalization techniques.
 *
 * Security Priority: #1
 * Performance Priority: #2
 * Developer Experience: #3
 */

/**
 * Decode Unicode escape sequences in a string
 * Handles: \u0041, \U00000041, \x41, etc.
 * @param {string} input - Input string potentially containing Unicode escapes
 * @returns {string} Decoded string
 */
function decodeUnicode (input) {
  if (typeof input !== 'string') return input

  let decoded = input

  // Handle \uXXXX format (JavaScript Unicode)
  decoded = decoded.replace(/\\u([0-9a-fA-F]{4})/g, (match, hex) => {
    return String.fromCharCode(parseInt(hex, 16))
  })

  // Handle \UXXXXXXXX format (8-digit Unicode)
  decoded = decoded.replace(/\\U([0-9a-fA-F]{8})/g, (match, hex) => {
    const codePoint = parseInt(hex, 16)
    return String.fromCodePoint(codePoint)
  })

  // Handle \xXX format (hex escape)
  decoded = decoded.replace(/\\x([0-9a-fA-F]{2})/g, (match, hex) => {
    return String.fromCharCode(parseInt(hex, 16))
  })

  // Handle HTML numeric entities &#xHH; and &#DD;
  decoded = decoded.replace(/&#x([0-9a-fA-F]+);/gi, (match, hex) => {
    return String.fromCharCode(parseInt(hex, 16))
  })

  decoded = decoded.replace(/&#(\d+);/g, (match, dec) => {
    return String.fromCharCode(parseInt(dec, 10))
  })

  return decoded
}

/**
 * Decode URL-encoded sequences recursively
 * Handles single, double, and triple encoding
 * @param {string} input - URL-encoded string
 * @param {number} maxDepth - Maximum decoding depth (default 3)
 * @returns {string} Decoded string
 */
function decodeUrl (input, maxDepth = 3) {
  if (typeof input !== 'string') return input

  let decoded = input
  let previousDecoded = ''
  let depth = 0

  // Recursively decode until no more changes or max depth reached
  while (decoded !== previousDecoded && depth < maxDepth) {
    previousDecoded = decoded
    try {
      decoded = decodeURIComponent(decoded)
    } catch (e) {
      // If decoding fails, try partial decoding
      decoded = decoded.replace(/%([0-9a-fA-F]{2})/g, (match, hex) => {
        return String.fromCharCode(parseInt(hex, 16))
      })
    }
    depth++
  }

  return decoded
}

/**
 * Normalize path separators and remove null bytes
 * Handles Windows backslashes, null bytes, and mixed separators
 * @param {string} input - Path string
 * @returns {string} Normalized path
 */
function normalizePath (input) {
  if (typeof input !== 'string') return input

  let normalized = input

  // Remove null bytes
  normalized = normalized.replace(/\0/g, '')

  // Convert all backslashes to forward slashes
  normalized = normalized.replace(/\\/g, '/')

  // Remove multiple consecutive slashes
  normalized = normalized.replace(/\/+/g, '/')

  // Decode Unicode path separators
  normalized = normalized.replace(/\\u002f/gi, '/')
  normalized = normalized.replace(/\\u005c/gi, '/')

  return normalized
}

/**
 * Strip dangerous characters for command execution
 * SECURITY FIX: Replace newlines with spaces instead of removing them
 * to prevent command concatenation attacks like "ls\nrm -rf /" -> "lsrm -rf /"
 * @param {string} input - Command string
 * @returns {string} Sanitized command
 */
function stripDangerousChars (input) {
  if (typeof input !== 'string') return input

  let sanitized = input

  // Remove null bytes
  sanitized = sanitized.replace(/\0/g, '')

  // SECURITY FIX: Replace newlines and carriage returns with spaces
  // This prevents "cmd1\ncmd2" from becoming "cmd1cmd2"
  sanitized = sanitized.replace(/[\r\n]/g, ' ')

  // Remove other control characters (0x00-0x1F, 0x7F) except space (0x20)
  // eslint-disable-next-line no-control-regex
  sanitized = sanitized.replace(/[\x00-\x08\x0E-\x1F\x7F]/g, '')

  // Remove zero-width characters
  sanitized = sanitized.replace(/[\u200B-\u200D\uFEFF]/g, '')

  // Clean up multiple spaces
  sanitized = sanitized.replace(/\s+/g, ' ').trim()

  return sanitized
}

/**
 * Comprehensive input decoder that applies all decoding techniques
 * This is the main entry point for security decoding
 * @param {string} input - Input string to decode
 * @param {Object} options - Decoding options
 * @returns {Object} Decoded result with metadata
 */
function securityDecode (input, options = {}) {
  const {
    decodeUnicode: doUnicode = true,
    decodeUrl: doUrl = true,
    normalizePath: doPath = true,
    stripDangerous: doStrip = true,
    maxIterations = 3
  } = options

  if (typeof input !== 'string') {
    return {
      decoded: input,
      wasDecoded: false,
      decodingSteps: [],
      originalInput: input
    }
  }

  const decodingSteps = []
  let decoded = input
  let previousDecoded = ''
  let iterations = 0

  // Apply decoding in multiple passes to handle nested encoding
  while (decoded !== previousDecoded && iterations < maxIterations) {
    previousDecoded = decoded

    // Step 1: URL decoding (deepest layer first)
    if (doUrl) {
      const urlDecoded = decodeUrl(decoded)
      if (urlDecoded !== decoded) {
        decodingSteps.push('url-decode')
        decoded = urlDecoded
      }
    }

    // Step 2: Unicode decoding
    if (doUnicode) {
      const unicodeDecoded = decodeUnicode(decoded)
      if (unicodeDecoded !== decoded) {
        decodingSteps.push('unicode-decode')
        decoded = unicodeDecoded
      }
    }

    // Step 3: Path normalization
    if (doPath) {
      const pathNormalized = normalizePath(decoded)
      if (pathNormalized !== decoded) {
        decodingSteps.push('path-normalize')
        decoded = pathNormalized
      }
    }

    // Step 4: Strip dangerous characters
    if (doStrip) {
      const stripped = stripDangerousChars(decoded)
      if (stripped !== decoded) {
        decodingSteps.push('strip-dangerous')
        decoded = stripped
      }
    }

    iterations++
  }

  return {
    decoded,
    wasDecoded: decoded !== input,
    decodingSteps,
    originalInput: input,
    iterations
  }
}

/**
 * Check if input contains any encoded sequences
 * Used to detect potential bypass attempts
 * @param {string} input - Input to check
 * @returns {boolean} True if encoding detected
 */
function hasEncoding (input) {
  if (typeof input !== 'string') return false

  const encodingPatterns = [
    /%[0-9a-fA-F]{2}/, // URL encoding
    /\\u[0-9a-fA-F]{4}/, // Unicode \uXXXX
    /\\U[0-9a-fA-F]{8}/, // Unicode \UXXXXXXXX
    /\\x[0-9a-fA-F]{2}/, // Hex \xXX
    /&#x[0-9a-fA-F]+;/, // HTML hex entity
    /&#\d+;/, // HTML decimal entity
    /\0/, // Null byte
    /[\r\n]/, // Newlines
    /\\/ // Backslash (potential path separator)
  ]

  return encodingPatterns.some(pattern => pattern.test(input))
}

/**
 * Constant-time string comparison to prevent timing attacks
 * @param {string} a - First string
 * @param {string} b - Second string
 * @returns {boolean} True if strings are equal
 */
function constantTimeCompare (a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return a === b
  }

  if (a.length !== b.length) {
    return false
  }

  let result = 0
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i)
  }

  return result === 0
}

/**
 * Add random micro-delay to mask processing time
 * Used for timing attack mitigation
 * @returns {Promise<void>}
 */
async function addTimingNoise () {
  const delay = Math.random() * 2 // 0-2ms random delay
  return new Promise(resolve => setTimeout(resolve, delay))
}

module.exports = {
  decodeUnicode,
  decodeUrl,
  normalizePath,
  stripDangerousChars,
  securityDecode,
  hasEncoding,
  constantTimeCompare,
  addTimingNoise
}
