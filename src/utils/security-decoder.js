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

const unorm = require('unorm')

// Homograph mapping for common attack vectors
// Maps confusable Unicode characters to their ASCII equivalents
const HOMOGRAPH_MAP = {
  // Cyrillic lookalikes (most common in attacks)
  'а': 'a', // U+0430
  'е': 'e', // U+0435
  'о': 'o', // U+043E
  'р': 'p', // U+0440
  'с': 'c', // U+0441
  'у': 'y', // U+0443
  'х': 'x', // U+0445
  'А': 'A', // U+0410
  'В': 'B', // U+0412
  'Е': 'E', // U+0415
  'К': 'K', // U+041A
  'М': 'M', // U+041C
  'Н': 'H', // U+041D
  'О': 'O', // U+041E
  'Р': 'P', // U+0420
  'С': 'C', // U+0421
  'Т': 'T', // U+0422
  'Х': 'X', // U+0425
  // Greek lookalikes
  'α': 'a', // U+03B1
  'ο': 'o', // U+03BF
  'ρ': 'p', // U+03C1
  'τ': 't', // U+03C4
  'υ': 'u', // U+03C5
  'χ': 'x', // U+03C7
  // Mathematical alphanumeric symbols (various styles)
  '𝐚': 'a', '𝐛': 'b', '𝐜': 'c', '𝐝': 'd', '𝐞': 'e', '𝐟': 'f',
  '𝐀': 'A', '𝐁': 'B', '𝐂': 'C', '𝐃': 'D', '𝐄': 'E', '𝐅': 'F',
  '𝒂': 'a', '𝒃': 'b', '𝒄': 'c', '𝒅': 'd', '𝒆': 'e', '𝒇': 'f',
  '𝒸': 'c', '𝒶': 'a', '𝓉': 't', '𝓅': 'p', '𝓈': 's', '𝓌': 'w',
  '𝓬': 'c', '𝓪': 'a', '𝓽': 't'
}

/**
 * Normalize Unicode and replace homographs
 * @param {string} input - Input string to normalize
 * @returns {string} Normalized string with homographs replaced
 */
function normalizeUnicode(input) {
  if (typeof input !== 'string') return input
  
  // First normalize to NFC (Canonical Composition)
  let normalized = unorm.nfc(input)
  
  // Replace homographs with ASCII equivalents
  for (const [homograph, ascii] of Object.entries(HOMOGRAPH_MAP)) {
    normalized = normalized.replace(new RegExp(homograph, 'g'), ascii)
  }
  
  return normalized
}

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

  // CRITICAL: Remove ALL control characters first, including null bytes
  // This MUST happen before any other processing
  // eslint-disable-next-line no-control-regex
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/g, '')

  // SECURITY FIX: Replace newlines and carriage returns with spaces
  // This prevents "cmd1\ncmd2" from becoming "cmd1cmd2"
  sanitized = sanitized.replace(/[\r\n]/g, ' ')

  // Remove zero-width and directional characters
  // U+200B-U+200F: Zero-width spaces and joiners
  // U+202A-U+202E: Directional formatting (LTR, RTL overrides)
  // U+2060-U+2069: Word joiners and directional isolates
  // U+FEFF: Zero-width no-break space
  sanitized = sanitized.replace(/[\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF]/g, '')

  // Remove other dangerous Unicode categories
  sanitized = sanitized.replace(/[\uFFF0-\uFFFF]/g, '') // Specials block
  sanitized = sanitized.replace(/[\uDB40-\uDB7F]/g, '') // High surrogates for private use

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
    normalizeUnicode: doNormalize = true,
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

  // CRITICAL: Apply Unicode normalization FIRST to handle homographs
  if (doNormalize) {
    const normalized = normalizeUnicode(decoded)
    if (normalized !== decoded) {
      decodingSteps.push('unicode-normalize')
      decoded = normalized
    }
  }

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

    // Step 5: Re-normalize after decoding (catches encoded homographs)
    if (doNormalize) {
      const reNormalized = normalizeUnicode(decoded)
      if (reNormalized !== decoded) {
        decodingSteps.push('unicode-renormalize')
        decoded = reNormalized
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

// Lazy load security enhancements to avoid circular dependency
function getSecurityEnhancements() {
  return require('./security-enhancements');
}

/**
 * Enhanced security decode with all security checks
 * @param {string} input - Input to decode
 * @param {Object} options - Decoding and security options
 * @returns {Promise<Object>} Enhanced decode result
 */
async function enhancedSecurityDecode (input, options = {}) {
  const {
    // Existing decode options
    decodeUnicode: doUnicode = true,
    decodeUrl: doUrl = true,
    normalizePath: doPath = true,
    stripDangerous: doStrip = true,
    normalizeUnicode: doNormalize = true,
    maxIterations = 3,
    
    // New security enhancement options
    checkDirectionalOverrides = true,
    checkNullBytes = true,
    checkMultipleEncoding = true,
    checkCyrillicHomographs = true,
    ensureTimingConsistency = true,
    maxEncodingDepth = 4
  } = options

  if (ensureTimingConsistency) {
    const { ensureTimingConsistency: ensureTimingFunction } = require('./security-enhancements')
    return ensureTimingFunction(async () => {
      return performEnhancedDecode()
    }, 100) // 100ms baseline for comprehensive decode
  }

  return performEnhancedDecode()

  async function performEnhancedDecode () {
    // Start with basic security decode
    const basicResult = securityDecode(input, {
      decodeUnicode: doUnicode,
      decodeUrl: doUrl,
      normalizePath: doPath,
      stripDangerous: doStrip,
      normalizeUnicode: doNormalize,
      maxIterations
    })

    const result = {
      decoded: basicResult.decoded,
      wasDecoded: basicResult.wasDecoded,
      decodingSteps: basicResult.decodingSteps,
      originalInput: basicResult.originalInput,
      iterations: basicResult.iterations,
      warnings: [],
      securityChecks: {}
    }

    // Apply security enhancements
    if (checkDirectionalOverrides) {
      const { detectDirectionalOverrides } = getSecurityEnhancements();
      const dirResult = detectDirectionalOverrides(result.decoded)
      if (dirResult.detected) {
        result.warnings.push(...dirResult.warnings)
        result.decoded = dirResult.sanitized
        result.securityChecks.directionalOverrides = dirResult.metadata
      }
    }

    if (checkNullBytes) {
      const { detectNullBytes } = getSecurityEnhancements();
      const nullResult = detectNullBytes(result.decoded)
      if (nullResult.detected) {
        result.warnings.push(...nullResult.warnings)
        result.decoded = nullResult.sanitized
        result.securityChecks.nullBytes = nullResult.metadata
      }
    }

    if (checkMultipleEncoding) {
      const { detectMultipleUrlEncoding } = getSecurityEnhancements();
      const encodingResult = detectMultipleUrlEncoding(input, maxEncodingDepth)
      if (encodingResult.detected) {
        result.warnings.push(...encodingResult.warnings)
        result.securityChecks.multipleEncoding = encodingResult.metadata
        
        // Use the more thoroughly decoded version if different
        if (encodingResult.decoded !== result.decoded) {
          result.decoded = encodingResult.decoded
          result.wasDecoded = true
        }
      }
    }

    if (checkCyrillicHomographs) {
      const { detectCyrillicHomographs } = getSecurityEnhancements();
      const homographResult = detectCyrillicHomographs(result.decoded)
      if (homographResult.detected) {
        result.warnings.push(...homographResult.warnings)
        result.decoded = homographResult.normalized
        result.securityChecks.cyrillicHomographs = homographResult.metadata
      }
    }

    return result
  }
}

module.exports = {
  normalizeUnicode,
  decodeUnicode,
  decodeUrl,
  normalizePath,
  stripDangerousChars,
  securityDecode,
  hasEncoding,
  constantTimeCompare,
  addTimingNoise,
  enhancedSecurityDecode
}
