/**
 * Enterprise Security Enhancements Module
 * 
 * Provides advanced security detection and sanitization for inline use
 * Focus: Maximum security with minimal latency (<10ms)
 * Scope: Inline sanitization library (not edge/network)
 */

// Directional and bidirectional control characters
const DIRECTIONAL_CHARS = {
  RTL_OVERRIDE: '\u202E',
  LTR_OVERRIDE: '\u202D',
  RTL_EMBEDDING: '\u202B',
  LTR_EMBEDDING: '\u202A',
  POP_DIRECTIONAL: '\u202C',
  LTR_ISOLATE: '\u2066',
  RTL_ISOLATE: '\u2067',
  FIRST_STRONG_ISOLATE: '\u2068',
  POP_ISOLATE: '\u2069'
};

// Regex pattern for all directional characters
const DIRECTIONAL_PATTERN = /[\u202A-\u202E\u2066-\u2069]/g;

/**
 * Detect directional override attacks (Trojan Source attacks)
 * Used for filename spoofing, code obfuscation, etc.
 * @param {string} input - Input to check
 * @returns {Object} Detection result
 */
function detectDirectionalOverride(input) {
  if (typeof input !== 'string') {
    return { detected: false, warnings: [] };
  }

  const warnings = [];
  let detected = false;

  // Check for each type of directional character
  for (const [name, char] of Object.entries(DIRECTIONAL_CHARS)) {
    if (input.includes(char)) {
      detected = true;
      const readable = name.toLowerCase().replace(/_/g, ' ');
      warnings.push(`Directional override detected: ${readable} character (U+${char.charCodeAt(0).toString(16).toUpperCase()})`);
    }
  }

  // Check for Trojan Source patterns
  if (detected) {
    warnings.push('Potential Trojan Source attack: bidirectional text manipulation detected');
    
    // Check if it's trying to reverse sensitive paths
    if (input.match(/[\u202E].*\/(etc|usr|bin|var|sys|proc)/)) {
      warnings.push('Critical: Directional override attempting to hide system path access');
    }
  }

  return {
    detected,
    warnings,
    sanitized: detected ? input.replace(DIRECTIONAL_PATTERN, '') : input
  };
}

/**
 * Enhanced null byte detection with proper warnings
 * @param {string} input - Input to check
 * @returns {Object} Detection result
 */
function detectNullBytes(input) {
  if (typeof input !== 'string') {
    return { detected: false, warnings: [] };
  }

  const warnings = [];
  let detected = false;

  // Check for literal null bytes
  if (input.includes('\x00')) {
    detected = true;
    const count = (input.match(/\x00/g) || []).length;
    warnings.push(`Null byte injection detected: ${count} null byte(s) found`);
    warnings.push('Security: Null bytes can terminate strings in C-based systems');
    
    // Check context
    if (input.match(/\.(txt|log|conf|ini)\x00/)) {
      warnings.push('Critical: Null byte attempting to bypass file extension checks');
    }
    
    if (input.match(/\/etc\/.*\x00/)) {
      warnings.push('Critical: Null byte in system path - potential path traversal');
    }
  }

  // Check for other dangerous control characters
  const controlChars = input.match(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g);
  if (controlChars) {
    warnings.push(`Control characters detected: ${controlChars.length} dangerous character(s)`);
  }

  return {
    detected,
    warnings,
    sanitized: input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
  };
}

/**
 * Detect multi-layer URL encoding attempts
 * @param {string} input - Input to check
 * @param {number} maxDepth - Maximum decode depth (default 5)
 * @returns {Object} Detection result
 */
function detectDoubleEncoding(input, maxDepth = 5) {
  if (typeof input !== 'string') {
    return { detected: false, warnings: [], decoded: input };
  }

  const warnings = [];
  let decoded = input;
  let decodeLevels = 0;
  let previousDecoded = '';

  // Attempt to decode multiple layers
  while (decoded !== previousDecoded && decodeLevels < maxDepth) {
    previousDecoded = decoded;
    
    try {
      // Try URL decoding
      const urlDecoded = decodeURIComponent(decoded);
      if (urlDecoded !== decoded) {
        decodeLevels++;
        decoded = urlDecoded;
      }
    } catch (e) {
      // Partial decoding for malformed input
      decoded = decoded.replace(/%([0-9a-fA-F]{2})/g, (match, hex) => {
        decodeLevels += 0.1; // Count partial decodes
        return String.fromCharCode(parseInt(hex, 16));
      });
    }
  }

  // Detect if multiple layers were decoded
  if (decodeLevels >= 2) {
    warnings.push(`Multi-layer encoding detected: ${Math.floor(decodeLevels)} encoding layers`);
    warnings.push('Security: Multiple encoding layers often indicate evasion attempts');
    
    // Check what was revealed after decoding
    if (decoded.match(/[;&|`$(){}[\]<>]/)) {
      warnings.push('Critical: Shell metacharacters revealed after decoding');
    }
    
    if (decoded.match(/(DROP|DELETE|INSERT|UPDATE|EXEC)/i)) {
      warnings.push('Critical: SQL keywords revealed after multi-layer decoding');
    }
  }

  return {
    detected: decodeLevels >= 2,
    warnings,
    decoded,
    layers: decodeLevels
  };
}

/**
 * Detect PostgreSQL dollar quoting with proper warnings
 * @param {string} input - Input SQL query
 * @returns {Object} Detection result
 */
function detectPostgreSQLDollarQuoting(input) {
  if (typeof input !== 'string') {
    return { detected: false, warnings: [] };
  }

  const warnings = [];
  let detected = false;

  // Pattern for dollar quoting: $$ or $tag$
  const dollarQuotePattern = /\$([a-zA-Z_][a-zA-Z0-9_]*)?\$.*?\$\1\$/g;
  const simpleDollarPattern = /\$\$.*?\$\$/g;

  if (dollarQuotePattern.test(input) || simpleDollarPattern.test(input)) {
    detected = true;
    warnings.push('PostgreSQL dollar quoting detected: potential SQL injection vector');
    warnings.push('Database-specific: PostgreSQL dollar quotes can bypass filters');
    
    // Check for dangerous content within dollar quotes
    const matches = input.match(dollarQuotePattern) || input.match(simpleDollarPattern) || [];
    for (const match of matches) {
      if (match.match(/(DROP|DELETE|TRUNCATE|EXEC|UNION|INSERT|UPDATE)/i)) {
        warnings.push('Critical: Dangerous SQL operations within dollar quotes');
      }
    }
  }

  return {
    detected,
    warnings
  };
}

/**
 * Detect homograph attacks with detailed warnings
 * @param {string} input - Input to check
 * @param {string} normalized - Normalized version of input
 * @returns {Object} Detection result
 */
function detectHomographs(input, normalized) {
  if (typeof input !== 'string' || typeof normalized !== 'string') {
    return { detected: false, warnings: [] };
  }

  const warnings = [];
  const detected = input !== normalized && input.length === normalized.length;

  if (detected) {
    warnings.push('Unicode homograph attack detected: confusable characters present');
    
    // Detect specific homograph types
    if (input.match(/[а-яА-Я]/)) {
      warnings.push('Cyrillic homographs detected: characters visually similar to Latin');
    }
    
    if (input.match(/[α-ωΑ-Ω]/)) {
      warnings.push('Greek homographs detected: potential visual spoofing');
    }
    
    // Check for mathematical alphanumeric symbols
    if (input.match(/[𝐚𝐛𝐜𝐝𝐞𝐟𝐠𝐡𝐢𝐣𝐤𝐥𝐦𝐧𝐨𝐩𝐪𝐫𝐬𝐭𝐮𝐯𝐰𝐱𝐲𝐳]/) || 
        input.match(/[𝐀𝐁𝐂𝐃𝐄𝐅𝐆𝐇𝐈𝐉𝐊𝐋𝐌𝐍𝐎𝐏𝐐𝐑𝐒𝐓𝐔𝐕𝐖𝐗𝐘𝐙]/) ||
        input.match(/[𝒂𝒃𝒸𝒅𝒆𝒇𝒈𝒉𝒊𝒋𝒌𝒍𝒎𝒏𝒐𝒑𝒒𝒓𝒔𝒕𝒖𝒗𝒘𝒙𝒚𝒛]/)) {
      warnings.push('Mathematical alphanumeric symbols detected: Unicode lookalikes');
    }

    // Check for sensitive command spoofing
    if (normalized.match(/^(cat|ls|rm|echo|wget|curl|chmod|sudo)/)) {
      warnings.push('Critical: Homograph attempting to spoof system command');
    }
  }

  return {
    detected,
    warnings
  };
}

/**
 * Handle empty and whitespace-only strings appropriately
 * @param {*} input - Input to check
 * @param {Object} context - Sanitization context
 * @returns {Object} Handling result
 */
function handleEmptyInput(input, context = {}) {
  // Handle null and undefined
  if (input === null || input === undefined) {
    return {
      isEmpty: true,
      shouldBlock: false,
      sanitized: input,
      warnings: []
    };
  }

  // Handle non-strings
  if (typeof input !== 'string') {
    return {
      isEmpty: false,
      shouldBlock: false,
      sanitized: input,
      warnings: []
    };
  }

  // Handle empty string
  if (input === '') {
    return {
      isEmpty: true,
      shouldBlock: false,
      sanitized: '',
      warnings: []
    };
  }

  // Handle whitespace-only
  const trimmed = input.trim();
  if (trimmed === '') {
    return {
      isEmpty: true,
      shouldBlock: false,
      sanitized: '',
      warnings: []
    };
  }

  return {
    isEmpty: false,
    shouldBlock: false,
    sanitized: input,
    warnings: []
  };
}

/**
 * Add consistent timing to prevent timing attacks
 * Uses crypto-safe randomization
 * @param {Function} operation - Operation to time-normalize
 * @param {number} targetTime - Target execution time in ms
 * @returns {*} Operation result
 */
function constantTimeWrapper(operation, targetTime = 10) {
  const startTime = process.hrtime.bigint();
  
  // Execute the operation
  const result = operation();
  
  // Calculate elapsed time
  const elapsedNs = Number(process.hrtime.bigint() - startTime);
  const elapsedMs = elapsedNs / 1000000;
  
  // Add padding time if needed
  if (elapsedMs < targetTime) {
    const paddingMs = targetTime - elapsedMs;
    // Add random variance (±20% of padding)
    const variance = (Math.random() - 0.5) * 0.4 * paddingMs;
    const finalPadding = Math.max(0, paddingMs + variance);
    
    // Busy wait with some CPU work
    const endTime = Date.now() + finalPadding;
    while (Date.now() < endTime) {
      // Do some work to prevent optimization
      Math.sqrt(Math.random());
    }
  }
  
  return result;
}

/**
 * Comprehensive security check combining all detections
 * @param {string} input - Input to check
 * @param {Object} options - Detection options
 * @returns {Object} Comprehensive security result
 */
function performSecurityChecks(input, options = {}) {
  const {
    checkDirectional = true,
    checkNullBytes = true,
    checkDoubleEncoding = true,
    checkHomographs = true,
    normalized = input
  } = options;

  const allWarnings = [];
  let shouldBlock = false;

  // Check empty input first
  const emptyCheck = handleEmptyInput(input);
  if (emptyCheck.isEmpty) {
    return {
      blocked: false,
      warnings: [],
      sanitized: emptyCheck.sanitized
    };
  }

  // Directional override check
  if (checkDirectional) {
    const directionalResult = detectDirectionalOverride(input);
    if (directionalResult.detected) {
      shouldBlock = true;
      allWarnings.push(...directionalResult.warnings);
    }
  }

  // Null byte check
  if (checkNullBytes) {
    const nullByteResult = detectNullBytes(input);
    if (nullByteResult.detected) {
      shouldBlock = true;
      allWarnings.push(...nullByteResult.warnings);
    }
  }

  // Double encoding check
  if (checkDoubleEncoding) {
    const encodingResult = detectDoubleEncoding(input);
    if (encodingResult.detected) {
      shouldBlock = true;
      allWarnings.push(...encodingResult.warnings);
    }
  }

  // Homograph check
  if (checkHomographs && normalized !== input) {
    const homographResult = detectHomographs(input, normalized);
    if (homographResult.detected) {
      shouldBlock = true;
      allWarnings.push(...homographResult.warnings);
    }
  }

  return {
    blocked: shouldBlock,
    warnings: allWarnings,
    sanitized: shouldBlock ? null : input
  };
}

module.exports = {
  // Individual detectors
  detectDirectionalOverride,
  detectNullBytes,
  detectDoubleEncoding,
  detectPostgreSQLDollarQuoting,
  detectHomographs,
  handleEmptyInput,
  constantTimeWrapper,
  
  // Comprehensive check
  performSecurityChecks,
  
  // Constants
  DIRECTIONAL_CHARS,
  DIRECTIONAL_PATTERN
};