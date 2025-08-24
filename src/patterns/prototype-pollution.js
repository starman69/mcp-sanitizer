/**
 * Prototype Pollution Pattern Detection Module
 *
 * Detects patterns commonly used in prototype pollution attacks, including
 * dangerous object keys, constructor manipulation, and prototype chain traversal.
 *
 * Based on security best practices from prototype pollution research,
 * OWASP guidelines, and common attack vectors in JavaScript applications.
 */

const SEVERITY_LEVELS = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low'
};

/**
 * Dangerous object keys that can lead to prototype pollution
 */
const DANGEROUS_KEYS = [
  '__proto__',
  'constructor',
  'prototype',
  'constructor.prototype',
  '__defineGetter__',
  '__defineSetter__',
  '__lookupGetter__',
  '__lookupSetter__',
  'hasOwnProperty',
  'isPrototypeOf',
  'propertyIsEnumerable',
  'toString',
  'valueOf'
];

/**
 * Patterns for prototype pollution in different contexts
 */
const POLLUTION_PATTERNS = [
  // Direct prototype manipulation
  /__proto__\s*[=:]/g,
  /constructor\s*\.\s*prototype\s*[=:]/g,
  /prototype\s*\.\s*constructor\s*[=:]/g,

  // Bracket notation access
  /\[\s*['"]__proto__['"]\s*\]/g,
  /\[\s*['"]constructor['"]\s*\]/g,
  /\[\s*['"]prototype['"]\s*\]/g,

  // Function constructor manipulation
  /constructor\s*\.\s*constructor\s*[=:]/g,
  /Function\s*\.\s*prototype\s*[=:]/g,
  /Object\s*\.\s*prototype\s*[=:]/g,

  // Array and object prototype pollution
  /Array\s*\.\s*prototype\s*\.\s*\w+\s*[=:]/g,
  /Object\s*\.\s*prototype\s*\.\s*\w+\s*[=:]/g,

  // Getter/setter manipulation
  /__defineGetter__\s*\(/g,
  /__defineSetter__\s*\(/g,
  /Object\s*\.\s*defineProperty\s*\(\s*.*prototype/g
];

/**
 * JSON-based prototype pollution patterns
 */
const JSON_POLLUTION_PATTERNS = [
  // JSON key patterns
  /"__proto__"\s*:/g,
  /"constructor"\s*:/g,
  /"prototype"\s*:/g,

  // Nested JSON pollution
  /"constructor"\s*:\s*{\s*"prototype"/g,
  /"__proto__"\s*:\s*{\s*"constructor"/g,

  // Unicode escaped versions
  /"\u005f\u005fproto\u005f\u005f"\s*:/g,
  /"\u0063onstructor"\s*:/g,

  // Hex escaped versions
  /"\x5f\x5fproto\x5f\x5f"\s*:/g,
  /"\x63onstructor"\s*:/g
];

/**
 * Lodash-specific pollution patterns
 */
const LODASH_POLLUTION_PATTERNS = [
  // Path-based pollution via lodash
  /lodash.*set.*__proto__/gi,
  /lodash.*merge.*__proto__/gi,
  /lodash.*defaults.*__proto__/gi,
  /_.set.*__proto__/g,
  /_.merge.*__proto__/g,
  /_.defaults.*__proto__/g,

  // Property path pollution
  /\[\s*'__proto__\..*'\s*\]/g,
  /\[\s*"__proto__\..*"\s*\]/g
];

/**
 * Express.js specific pollution patterns
 */
const EXPRESS_POLLUTION_PATTERNS = [
  // Body parser pollution
  /req\.body\.__proto__/g,
  /req\.query\.__proto__/g,
  /req\.params\.__proto__/g,

  // URL-encoded pollution
  /__proto__\[.*\]/g,
  /constructor\[prototype\]/g,
  /constructor\.prototype\[/g
];

/**
 * Encoding bypass patterns for prototype pollution
 */
const ENCODING_BYPASS_PATTERNS = [
  // URL encoding
  /%5f%5fproto%5f%5f/gi, // __proto__
  /%63onstructor/gi, // constructor
  /%70rototype/gi, // prototype

  // Unicode encoding
  /\\u005f\\u005fproto\\u005f\\u005f/gi,
  /\\u0063onstructor/gi,
  /\\u0070rototype/gi,

  // Hex encoding
  /\\x5f\\x5fproto\\x5f\\x5f/gi,
  /\\x63onstructor/gi,
  /\\x70rototype/gi,

  // Mixed case bypass
  /__PROTO__/gi,
  /CONSTRUCTOR/gi,
  /PROTOTYPE/gi
];

/**
 * Property access patterns that might indicate pollution
 */
const PROPERTY_ACCESS_PATTERNS = [
  // Dynamic property access
  /\[\s*.*proto.*\s*\]/gi,
  /\[\s*.*constructor.*\s*\]/gi,

  // Template literal access
  /\$\{.*__proto__.*\}/g,
  /\$\{.*constructor.*\}/g,

  // Computed property names
  /\[\s*['"]\w*proto\w*['"]\s*\]/gi,
  /\[\s*['"]\w*constructor\w*['"]\s*\]/gi
];

/**
 * Main detection function for prototype pollution patterns
 * @param {string|Object} input - The input to analyze (string or object)
 * @param {Object} options - Detection options
 * @returns {Object} Detection result with severity and details
 */
function detectPrototypePollution (input, options = {}) {
  const detectedPatterns = [];
  let maxSeverity = null;

  // Handle different input types
  if (typeof input === 'object' && input !== null) {
    const objectResult = checkObjectKeys(input);
    if (objectResult.detected) {
      detectedPatterns.push(...objectResult.patterns);
      maxSeverity = getHigherSeverity(maxSeverity, objectResult.severity);
    }
  }

  if (typeof input === 'string') {
    // Check pollution patterns
    const pollutionResult = checkPollutionPatterns(input);
    if (pollutionResult.detected) {
      detectedPatterns.push(...pollutionResult.patterns);
      maxSeverity = getHigherSeverity(maxSeverity, pollutionResult.severity);
    }

    // Check JSON pollution patterns
    const jsonResult = checkJSONPollutionPatterns(input);
    if (jsonResult.detected) {
      detectedPatterns.push(...jsonResult.patterns);
      maxSeverity = getHigherSeverity(maxSeverity, jsonResult.severity);
    }

    // Check lodash patterns
    const lodashResult = checkLodashPollutionPatterns(input);
    if (lodashResult.detected) {
      detectedPatterns.push(...lodashResult.patterns);
      maxSeverity = getHigherSeverity(maxSeverity, lodashResult.severity);
    }

    // Check Express patterns
    const expressResult = checkExpressPollutionPatterns(input);
    if (expressResult.detected) {
      detectedPatterns.push(...expressResult.patterns);
      maxSeverity = getHigherSeverity(maxSeverity, expressResult.severity);
    }

    // Check encoding bypass patterns
    const encodingResult = checkEncodingBypassPatterns(input);
    if (encodingResult.detected) {
      detectedPatterns.push(...encodingResult.patterns);
      maxSeverity = getHigherSeverity(maxSeverity, encodingResult.severity);
    }

    // Check property access patterns
    const propertyResult = checkPropertyAccessPatterns(input);
    if (propertyResult.detected) {
      detectedPatterns.push(...propertyResult.patterns);
      maxSeverity = getHigherSeverity(maxSeverity, propertyResult.severity);
    }
  }

  return {
    detected: detectedPatterns.length > 0,
    severity: maxSeverity,
    patterns: detectedPatterns,
    message: detectedPatterns.length > 0
      ? `Prototype pollution patterns detected: ${detectedPatterns.join(', ')}`
      : null
  };
}

/**
 * Check object keys for dangerous properties
 */
function checkObjectKeys (obj, prefix = '', visited = new WeakSet()) {
  if (visited.has(obj)) {
    return { detected: false, severity: null, patterns: [] };
  }
  visited.add(obj);

  const detected = [];

  try {
    for (const key of Object.keys(obj)) {
      const fullKey = prefix ? `${prefix}.${key}` : key;

      // Check if key is dangerous
      if (DANGEROUS_KEYS.includes(key)) {
        detected.push(`dangerous_key:${fullKey}`);
      }

      // Check for prototype pollution key patterns
      if (key.includes('__proto__') ||
          key.includes('constructor') ||
          key.includes('prototype')) {
        detected.push(`pollution_key:${fullKey}`);
      }

      // Recursively check nested objects
      if (typeof obj[key] === 'object' && obj[key] !== null) {
        const nestedResult = checkObjectKeys(obj[key], fullKey, visited);
        if (nestedResult.detected) {
          detected.push(...nestedResult.patterns);
        }
      }
    }
  } catch (error) {
    // Handle cases where object properties cannot be enumerated
    detected.push(`object_enumeration_error:${error.message}`);
  }

  return {
    detected: detected.length > 0,
    severity: detected.length > 0 ? SEVERITY_LEVELS.CRITICAL : null,
    patterns: detected
  };
}

/**
 * Check for prototype pollution patterns in strings
 */
function checkPollutionPatterns (input) {
  const detected = [];

  for (const pattern of POLLUTION_PATTERNS) {
    if (pattern.test(input)) {
      detected.push(`pollution_pattern:${pattern.source}`);
    }
  }

  return {
    detected: detected.length > 0,
    severity: detected.length > 0 ? SEVERITY_LEVELS.CRITICAL : null,
    patterns: detected
  };
}

/**
 * Check for JSON-based pollution patterns
 */
function checkJSONPollutionPatterns (input) {
  const detected = [];

  for (const pattern of JSON_POLLUTION_PATTERNS) {
    if (pattern.test(input)) {
      detected.push(`json_pollution:${pattern.source}`);
    }
  }

  return {
    detected: detected.length > 0,
    severity: detected.length > 0 ? SEVERITY_LEVELS.HIGH : null,
    patterns: detected
  };
}

/**
 * Check for Lodash-specific pollution patterns
 */
function checkLodashPollutionPatterns (input) {
  const detected = [];

  for (const pattern of LODASH_POLLUTION_PATTERNS) {
    if (pattern.test(input)) {
      detected.push(`lodash_pollution:${pattern.source}`);
    }
  }

  return {
    detected: detected.length > 0,
    severity: detected.length > 0 ? SEVERITY_LEVELS.HIGH : null,
    patterns: detected
  };
}

/**
 * Check for Express.js specific pollution patterns
 */
function checkExpressPollutionPatterns (input) {
  const detected = [];

  for (const pattern of EXPRESS_POLLUTION_PATTERNS) {
    if (pattern.test(input)) {
      detected.push(`express_pollution:${pattern.source}`);
    }
  }

  return {
    detected: detected.length > 0,
    severity: detected.length > 0 ? SEVERITY_LEVELS.HIGH : null,
    patterns: detected
  };
}

/**
 * Check for encoding bypass patterns
 */
function checkEncodingBypassPatterns (input) {
  const detected = [];

  for (const pattern of ENCODING_BYPASS_PATTERNS) {
    if (pattern.test(input)) {
      detected.push(`encoding_bypass:${pattern.source}`);
    }
  }

  return {
    detected: detected.length > 0,
    severity: detected.length > 0 ? SEVERITY_LEVELS.MEDIUM : null,
    patterns: detected
  };
}

/**
 * Check for suspicious property access patterns
 */
function checkPropertyAccessPatterns (input) {
  const detected = [];

  for (const pattern of PROPERTY_ACCESS_PATTERNS) {
    if (pattern.test(input)) {
      detected.push(`property_access:${pattern.source}`);
    }
  }

  return {
    detected: detected.length > 0,
    severity: detected.length > 0 ? SEVERITY_LEVELS.MEDIUM : null,
    patterns: detected
  };
}

/**
 * Get the higher severity between two severity levels
 */
function getHigherSeverity (current, newSeverity) {
  if (!current) return newSeverity;
  if (!newSeverity) return current;

  const severityOrder = [
    SEVERITY_LEVELS.LOW,
    SEVERITY_LEVELS.MEDIUM,
    SEVERITY_LEVELS.HIGH,
    SEVERITY_LEVELS.CRITICAL
  ];

  const currentIndex = severityOrder.indexOf(current);
  const newIndex = severityOrder.indexOf(newSeverity);

  return newIndex > currentIndex ? newSeverity : current;
}

/**
 * Simple boolean check for prototype pollution
 * @param {string|Object} input - The input to check
 * @returns {boolean} True if prototype pollution patterns are detected
 */
function isPrototypePollution (input) {
  return detectPrototypePollution(input).detected;
}

/**
 * Check if an object key is dangerous for prototype pollution
 * @param {string} key - The object key to check
 * @returns {boolean} True if the key is dangerous
 */
function isDangerousKey (key) {
  return DANGEROUS_KEYS.includes(key) ||
         key.includes('__proto__') ||
         key.includes('constructor') ||
         key.includes('prototype');
}

module.exports = {
  // Main detection functions
  detectPrototypePollution,
  isPrototypePollution,
  isDangerousKey,

  // Individual checkers
  checkObjectKeys,
  checkPollutionPatterns,
  checkJSONPollutionPatterns,
  checkLodashPollutionPatterns,
  checkExpressPollutionPatterns,
  checkEncodingBypassPatterns,
  checkPropertyAccessPatterns,

  // Pattern exports for reuse
  DANGEROUS_KEYS,
  POLLUTION_PATTERNS,
  JSON_POLLUTION_PATTERNS,
  LODASH_POLLUTION_PATTERNS,
  EXPRESS_POLLUTION_PATTERNS,
  ENCODING_BYPASS_PATTERNS,
  PROPERTY_ACCESS_PATTERNS,

  // Constants
  SEVERITY_LEVELS
};
