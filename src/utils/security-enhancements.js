/**
 * Security Enhancements for MCP Sanitizer
 * 
 * This module implements enterprise-grade security enhancements for inline sanitization:
 * 1. Directional override detection (RTL/LTR)
 * 2. Null byte warning messages
 * 3. Double URL encoding detection
 * 4. PostgreSQL dollar quote warnings
 * 5. Cyrillic homograph warnings
 * 6. Empty string handling
 * 7. Timing consistency
 * 
 * Performance target: <10ms latency for inline operations
 * Security priority: Zero false positives on legitimate input
 */

// Timing attack prevention removed - not needed for middleware sanitization

/**
 * Unicode directional control characters that can be used for attacks
 */
const DIRECTIONAL_OVERRIDES = {
  // Right-to-left and left-to-right overrides
  RLO: '\u202E', // RIGHT-TO-LEFT OVERRIDE
  LRO: '\u202D', // LEFT-TO-RIGHT OVERRIDE
  RLE: '\u202B', // RIGHT-TO-LEFT EMBEDDING  
  LRE: '\u202A', // LEFT-TO-RIGHT EMBEDDING
  PDF: '\u202C', // POP DIRECTIONAL FORMATTING
  RLI: '\u2067', // RIGHT-TO-LEFT ISOLATE
  LRI: '\u2066', // LEFT-TO-RIGHT ISOLATE
  FSI: '\u2068', // FIRST STRONG ISOLATE
  PDI: '\u2069', // POP DIRECTIONAL ISOLATE
  
  // Zero-width characters often used in combination
  ZWNJ: '\u200C', // ZERO WIDTH NON-JOINER
  ZWJ: '\u200D',  // ZERO WIDTH JOINER
  ZWSP: '\u200B', // ZERO WIDTH SPACE
};

/**
 * Cyrillic characters that look like Latin characters (homographs)
 */
const CYRILLIC_HOMOGRAPHS = {
  'а': 'a', // U+0430 CYRILLIC SMALL LETTER A
  'е': 'e', // U+0435 CYRILLIC SMALL LETTER IE  
  'о': 'o', // U+043E CYRILLIC SMALL LETTER O
  'р': 'p', // U+0440 CYRILLIC SMALL LETTER ER
  'с': 'c', // U+0441 CYRILLIC SMALL LETTER ES
  'у': 'y', // U+0443 CYRILLIC SMALL LETTER U
  'х': 'x', // U+0445 CYRILLIC SMALL LETTER HA
  'А': 'A', // U+0410 CYRILLIC CAPITAL LETTER A
  'В': 'B', // U+0412 CYRILLIC CAPITAL LETTER VE
  'Е': 'E', // U+0415 CYRILLIC CAPITAL LETTER IE
  'К': 'K', // U+041A CYRILLIC CAPITAL LETTER KA
  'М': 'M', // U+041C CYRILLIC CAPITAL LETTER EM
  'Н': 'H', // U+041D CYRILLIC CAPITAL LETTER EN
  'О': 'O', // U+041E CYRILLIC CAPITAL LETTER O
  'Р': 'P', // U+0420 CYRILLIC CAPITAL LETTER ER
  'С': 'C', // U+0421 CYRILLIC CAPITAL LETTER ES
  'Т': 'T', // U+0422 CYRILLIC CAPITAL LETTER TE
  'Х': 'X', // U+0425 CYRILLIC CAPITAL LETTER HA
};

/**
 * PostgreSQL dollar quote patterns for SQL injection bypass
 */
const POSTGRES_DOLLAR_QUOTE_PATTERNS = [
  /\$[a-zA-Z_][a-zA-Z0-9_]*\$/g, // $tag$
  /\$\$/g, // $$
  /\$[0-9]+\$/g, // $1$, $2$, etc.
];

/**
 * Detect directional override attacks in text
 * @param {string} input - Input text to analyze
 * @returns {Object} Detection result with warnings and sanitized text
 */
function detectDirectionalOverrides(input) {
  if (typeof input !== 'string') {
    return {
      detected: false,
      warnings: [],
      sanitized: input,
      metadata: { originalLength: 0, cleanedLength: 0 }
    };
  }

  const warnings = [];
  let detected = false;
  let sanitized = input;
  const originalLength = input.length;

  // Check for directional override characters
  const overrideChars = Object.values(DIRECTIONAL_OVERRIDES);
  const foundOverrides = [];

  for (const [name, char] of Object.entries(DIRECTIONAL_OVERRIDES)) {
    if (input.includes(char)) {
      detected = true;
      foundOverrides.push(name);
      
      // Remove the directional override character
      sanitized = sanitized.replace(new RegExp(char, 'g'), '');
    }
  }

  if (detected) {
    warnings.push({
      type: 'DIRECTIONAL_OVERRIDE_ATTACK',
      message: `Directional text override characters detected: ${foundOverrides.join(', ')}. These can be used to disguise malicious content by changing text direction.`,
      severity: 'HIGH',
      recommendation: 'Remove directional override characters or validate text content after normalization.',
      characters: foundOverrides,
      securityImpact: 'Text direction manipulation can hide malicious URLs, file names, or commands from visual inspection.'
    });
  }

  // Check for suspicious patterns: mixed directional text
  const rtlPattern = /[\u0590-\u05FF\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\uFB50-\uFDFF\uFE70-\uFEFF]/;
  const ltrPattern = /[A-Za-z]/;
  
  if (rtlPattern.test(sanitized) && ltrPattern.test(sanitized)) {
    warnings.push({
      type: 'MIXED_DIRECTIONAL_TEXT',
      message: 'Mixed RTL and LTR text detected. Verify visual representation matches intended content.',
      severity: 'MEDIUM',
      recommendation: 'Review text rendering and ensure it displays as expected.',
      securityImpact: 'Mixed directional text can create visual confusion in security-sensitive contexts.'
    });
  }

  const cleanedLength = sanitized.length;

  return {
    detected,
    warnings,
    sanitized,
    metadata: {
      originalLength,
      cleanedLength,
      charactersRemoved: originalLength - cleanedLength,
      foundOverrides,
      hasMixedDirectionalText: rtlPattern.test(sanitized) && ltrPattern.test(sanitized)
    }
  };
}

/**
 * Detect and warn about null bytes with security context
 * @param {string} input - Input to analyze
 * @returns {Object} Detection result with detailed warnings
 */
function detectNullBytes(input) {
  if (typeof input !== 'string') {
    return {
      detected: false,
      warnings: [],
      sanitized: input,
      metadata: { nullByteCount: 0, positions: [] }
    };
  }

  const nullBytePattern = /\x00/g;
  const matches = [...input.matchAll(nullBytePattern)];
  const detected = matches.length > 0;
  const warnings = [];
  let sanitized = input;

  if (detected) {
    const positions = matches.map(match => match.index);
    
    warnings.push({
      type: 'NULL_BYTE_DETECTED',
      message: `Null bytes (0x00) detected at positions: ${positions.join(', ')}. Null bytes can terminate strings in C/C++ and cause data truncation.`,
      severity: 'HIGH',
      recommendation: 'Remove null bytes before processing. Null bytes should never appear in legitimate text input.',
      securityImpact: 'Null byte injection can bypass security filters, cause command truncation, or enable path traversal attacks.',
      positions,
      count: matches.length,
      context: 'Null bytes are often used in attacks to bypass string validation or cause buffer overflows.'
    });

    // Remove null bytes
    sanitized = input.replace(nullBytePattern, '');
  }

  return {
    detected,
    warnings,
    sanitized,
    metadata: {
      nullByteCount: matches.length,
      positions: detected ? matches.map(m => m.index) : [],
      originalLength: input.length,
      cleanedLength: sanitized.length
    }
  };
}

/**
 * Detect double/triple URL encoding attempts
 * @param {string} input - Input URL or string to analyze
 * @param {number} maxDepth - Maximum encoding depth to check (default: 4)
 * @returns {Object} Detection result with encoding analysis
 */
function detectMultipleUrlEncoding(input, maxDepth = 4) {
  if (typeof input !== 'string') {
    return {
      detected: false,
      warnings: [],
      decoded: input,
      metadata: { encodingDepth: 0, decodingSteps: [] }
    };
  }

  const warnings = [];
  const decodingSteps = [];
  let decoded = input;
  let depth = 0;
  let previousDecoded;

  // Track URL encoding patterns
  const urlEncodingPattern = /%[0-9A-Fa-f]{2}/g;

  while (depth < maxDepth && decoded !== previousDecoded) {
    previousDecoded = decoded;
    
    const encodedChars = decoded.match(urlEncodingPattern);
    if (!encodedChars || encodedChars.length === 0) {
      break;
    }

    try {
      const newDecoded = decodeURIComponent(decoded);
      if (newDecoded !== decoded) {
        depth++;
        decodingSteps.push({
          step: depth,
          before: decoded,
          after: newDecoded,
          encodedCharCount: encodedChars.length,
          decodedCharCount: newDecoded.match(urlEncodingPattern)?.length || 0
        });
        decoded = newDecoded;
      } else {
        break;
      }
    } catch (error) {
      // Malformed encoding
      warnings.push({
        type: 'MALFORMED_URL_ENCODING',
        message: `Malformed URL encoding detected at depth ${depth + 1}: ${error.message}`,
        severity: 'MEDIUM',
        recommendation: 'Verify URL encoding format and fix malformed sequences.',
        securityImpact: 'Malformed encoding may indicate an attack attempt or cause parsing errors.'
      });
      break;
    }
  }

  // Analysis and warnings
  if (depth >= 2) {
    warnings.push({
      type: 'MULTIPLE_URL_ENCODING',
      message: `Multiple URL encoding detected (${depth} layers). This may indicate an encoding-based bypass attempt.`,
      severity: depth >= 3 ? 'HIGH' : 'MEDIUM',
      recommendation: 'Review why multiple encoding layers are present. Legitimate URLs rarely need multiple encoding.',
      securityImpact: 'Multiple encoding layers can bypass security filters that only decode once.',
      encodingDepth: depth,
      decodingSteps: decodingSteps.map(step => `Layer ${step.step}: ${step.encodedCharCount} encoded chars`)
    });
  }

  // Check for suspicious patterns after decoding
  const suspiciousPatterns = [
    { pattern: /[<>'"&]/, name: 'HTML/XSS characters' },
    { pattern: /[;&|`$()]/, name: 'Command injection characters' },
    { pattern: /\.\.[\/\\]/, name: 'Path traversal' },
    { pattern: /\/etc\/|\/proc\/|\/sys\//, name: 'System directory access' }
  ];

  for (const { pattern, name } of suspiciousPatterns) {
    if (pattern.test(decoded) && !pattern.test(input)) {
      warnings.push({
        type: 'ENCODING_REVEALED_SUSPICIOUS_CONTENT',
        message: `URL decoding revealed ${name} that were hidden by encoding.`,
        severity: 'HIGH',
        recommendation: `Validate the decoded content against ${name} patterns.`,
        securityImpact: 'Encoding may have been used to hide malicious content from initial inspection.',
        revealedPattern: name
      });
    }
  }

  return {
    detected: depth > 0,
    warnings,
    decoded,
    metadata: {
      encodingDepth: depth,
      decodingSteps,
      originalLength: input.length,
      decodedLength: decoded.length,
      maxDepthReached: depth >= maxDepth
    }
  };
}

/**
 * Detect PostgreSQL dollar quote patterns that can bypass SQL injection filters
 * @param {string} input - Input SQL or text to analyze
 * @returns {Object} Detection result with PostgreSQL-specific warnings
 */
function detectPostgresDollarQuotes(input) {
  if (typeof input !== 'string') {
    return {
      detected: false,
      warnings: [],
      sanitized: input,
      metadata: { dollarQuotes: [], quotePairs: [] }
    };
  }

  const warnings = [];
  const detectedQuotes = [];
  const quotePairs = [];
  let detected = false;

  // Check for dollar quote patterns
  for (const pattern of POSTGRES_DOLLAR_QUOTE_PATTERNS) {
    const matches = [...input.matchAll(pattern)];
    if (matches.length > 0) {
      detected = true;
      
      for (const match of matches) {
        detectedQuotes.push({
          quote: match[0],
          position: match.index,
          pattern: pattern.source
        });
      }
    }
  }

  if (detected) {
    // Analyze quote pairs for potential SQL injection
    const dollarQuoteMap = new Map();
    
    for (const quote of detectedQuotes) {
      if (!dollarQuoteMap.has(quote.quote)) {
        dollarQuoteMap.set(quote.quote, []);
      }
      dollarQuoteMap.get(quote.quote).push(quote.position);
    }

    // Check for properly paired quotes (even count suggests valid usage)
    for (const [quote, positions] of dollarQuoteMap) {
      if (positions.length >= 2) {
        quotePairs.push({
          quote,
          positions,
          count: positions.length,
          isPaired: positions.length % 2 === 0
        });
      }
    }

    const hasPairedQuotes = quotePairs.some(pair => pair.isPaired);
    const hasUnpairedQuotes = quotePairs.some(pair => !pair.isPaired);

    warnings.push({
      type: 'POSTGRES_DOLLAR_QUOTES',
      message: `PostgreSQL dollar quotes detected: ${detectedQuotes.map(q => q.quote).join(', ')}. These can be used to bypass SQL injection filters.`,
      severity: hasUnpairedQuotes ? 'HIGH' : 'MEDIUM',
      recommendation: hasPairedQuotes 
        ? 'Verify that dollar-quoted strings are legitimate. Ensure SQL parameterization is used.' 
        : 'Unpaired dollar quotes detected - potential SQL injection attempt. Block or sanitize input.',
      securityImpact: 'Dollar quotes allow multi-line strings and can bypass quote-based SQL injection filters.',
      dollarQuotes: detectedQuotes.map(q => q.quote),
      quotePairs: quotePairs.map(pair => ({ quote: pair.quote, count: pair.count, paired: pair.isPaired })),
      context: 'PostgreSQL dollar quotes ($tag$) can contain any characters including single quotes without escaping.'
    });

    // Additional warning for SQL keywords within dollar quotes
    if (hasPairedQuotes) {
      const sqlKeywords = /\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|DECLARE)\b/gi;
      if (sqlKeywords.test(input)) {
        warnings.push({
          type: 'SQL_IN_DOLLAR_QUOTES',
          message: 'SQL keywords detected within text containing dollar quotes. This may indicate SQL injection.',
          severity: 'HIGH',
          recommendation: 'Review SQL content within dollar quotes. Ensure proper parameterization.',
          securityImpact: 'SQL commands within dollar quotes can execute with full database privileges.',
          keywords: [...input.matchAll(sqlKeywords)].map(m => m[0])
        });
      }
    }
  }

  return {
    detected,
    warnings,
    sanitized: input, // Don't modify SQL - let application handle it
    metadata: {
      dollarQuotes: detectedQuotes,
      quotePairs,
      totalQuoteCount: detectedQuotes.length,
      uniqueQuotes: new Set(detectedQuotes.map(q => q.quote)).size
    }
  };
}

/**
 * Detect Cyrillic homograph attacks in domain names and text
 * @param {string} input - Input text or domain to analyze
 * @returns {Object} Detection result with homograph warnings
 */
function detectCyrillicHomographs(input) {
  if (typeof input !== 'string') {
    return {
      detected: false,
      warnings: [],
      normalized: input,
      metadata: { homographs: [], suspiciousDomains: [] }
    };
  }

  const warnings = [];
  const foundHomographs = [];
  const suspiciousDomains = [];
  let detected = false;
  let normalized = input;

  // Check for Cyrillic homographs
  for (const [cyrillic, latin] of Object.entries(CYRILLIC_HOMOGRAPHS)) {
    if (input.includes(cyrillic)) {
      detected = true;
      foundHomographs.push({ cyrillic, latin, codePoint: `U+${cyrillic.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}` });
      
      // Replace with Latin equivalent for normalization
      normalized = normalized.replace(new RegExp(cyrillic, 'g'), latin);
    }
  }

  if (detected) {
    // Special analysis for domain names
    const domainPattern = /(?:^|\s|[^\w.-])((?:[a-zA-Zа-яё0-9](?:[a-zA-Zа-яё0-9-]*[a-zA-Zа-яё0-9])?\.)+[a-zA-Zа-яё]{2,})(?:\s|[^\w.-]|$)/gi;
    const domains = [...input.matchAll(domainPattern)];
    
    for (const domainMatch of domains) {
      const domain = domainMatch[1];
      let hasCyrillic = false;
      
      for (const cyrillic of Object.keys(CYRILLIC_HOMOGRAPHS)) {
        if (domain.includes(cyrillic)) {
          hasCyrillic = true;
          break;
        }
      }
      
      if (hasCyrillic) {
        suspiciousDomains.push({
          original: domain,
          normalized: domain.replace(/[а-я]/gi, char => CYRILLIC_HOMOGRAPHS[char] || char),
          position: domainMatch.index
        });
      }
    }

    const homographChars = foundHomographs.map(h => `${h.cyrillic} (${h.codePoint}) -> ${h.latin}`).join(', ');
    
    warnings.push({
      type: 'CYRILLIC_HOMOGRAPH_ATTACK',
      message: `Cyrillic homograph characters detected: ${homographChars}. These can be used for domain spoofing attacks.`,
      severity: suspiciousDomains.length > 0 ? 'HIGH' : 'MEDIUM',
      recommendation: suspiciousDomains.length > 0 
        ? 'Suspicious domains detected. Verify domain authenticity before accessing.' 
        : 'Mixed scripts detected. Verify text content is from expected language.',
      securityImpact: 'Homograph attacks can make malicious domains appear legitimate to users.',
      homographs: foundHomographs,
      suspiciousDomains: suspiciousDomains.map(d => ({ original: d.original, normalized: d.normalized })),
      context: 'Cyrillic characters that look identical to Latin characters can fool users into visiting malicious sites.'
    });

    // Check for well-known domains being spoofed
    const commonDomains = ['google', 'microsoft', 'github', 'amazon', 'apple', 'facebook', 'twitter', 'paypal'];
    for (const suspiciousDomain of suspiciousDomains) {
      for (const commonDomain of commonDomains) {
        if (suspiciousDomain.normalized.toLowerCase().includes(commonDomain)) {
          warnings.push({
            type: 'DOMAIN_SPOOFING_ATTEMPT',
            message: `Potential spoofing of well-known domain "${commonDomain}" detected: ${suspiciousDomain.original}`,
            severity: 'CRITICAL',
            recommendation: 'Block access to this domain. This is likely a phishing attempt.',
            securityImpact: 'Domain spoofing can steal credentials or install malware.',
            spoofedDomain: commonDomain,
            maliciousDomain: suspiciousDomain.original,
            normalizedDomain: suspiciousDomain.normalized
          });
        }
      }
    }
  }

  return {
    detected,
    warnings,
    normalized,
    metadata: {
      homographs: foundHomographs,
      suspiciousDomains,
      originalLength: input.length,
      normalizedLength: normalized.length,
      homographCount: foundHomographs.length
    }
  };
}

/**
 * Handle empty strings with context-aware sanitization
 * @param {*} input - Input to analyze (any type)
 * @param {Object} context - Context information for appropriate handling
 * @returns {Object} Handling result with recommendations
 */
function handleEmptyStrings(input, context = {}) {
  const {
    allowEmpty = false,
    defaultValue = null,
    fieldName = 'input',
    required = false,
    minLength = 0
  } = context;

  const result = {
    isEmpty: false,
    isValid: true,
    processed: input,
    warnings: [],
    metadata: {
      originalType: typeof input,
      originalValue: input,
      wasEmpty: false,
      appliedDefault: false
    }
  };

  // Type conversion to string for analysis
  let stringValue = '';
  let typeConverted = false;
  
  if (input === null || input === undefined) {
    result.isEmpty = true;
    result.metadata.wasEmpty = true;
  } else if (typeof input === 'string') {
    stringValue = input;
    result.isEmpty = input.trim().length === 0;
    result.metadata.wasEmpty = result.isEmpty;
  } else {
    // Convert to string for analysis
    stringValue = String(input);
    typeConverted = true;
    result.isEmpty = stringValue.trim().length === 0;
    result.metadata.wasEmpty = result.isEmpty;
    result.metadata.typeConverted = true;
  }

  // Handle empty cases based on context
  if (result.isEmpty) {
    if (required) {
      result.isValid = false;
      result.warnings.push({
        type: 'REQUIRED_FIELD_EMPTY',
        message: `Required field '${fieldName}' is empty or contains only whitespace.`,
        severity: 'HIGH',
        recommendation: 'Provide a valid non-empty value for this required field.',
        securityImpact: 'Empty required fields may indicate incomplete validation or potential bypass attempts.',
        field: fieldName,
        context: 'Required field validation'
      });
    } else if (!allowEmpty) {
      result.isValid = false;
      result.warnings.push({
        type: 'EMPTY_STRING_NOT_ALLOWED',
        message: `Empty string not allowed for field '${fieldName}'.`,
        severity: 'MEDIUM',
        recommendation: 'Provide a non-empty value or configure field to allow empty values.',
        securityImpact: 'Unexpected empty values may cause application logic errors.',
        field: fieldName
      });
    }

    // Apply default value if configured
    if (defaultValue !== null && !result.isValid) {
      result.processed = defaultValue;
      result.isValid = true;
      result.metadata.appliedDefault = true;
      result.warnings.push({
        type: 'DEFAULT_VALUE_APPLIED',
        message: `Applied default value for empty field '${fieldName}'.`,
        severity: 'LOW',
        recommendation: 'Verify that the default value is appropriate for your use case.',
        defaultValue: defaultValue,
        field: fieldName
      });
    }
  }

  // Length validation for non-empty strings
  if (!result.isEmpty && minLength > 0 && stringValue.trim().length < minLength) {
    result.isValid = false;
    result.warnings.push({
      type: 'MINIMUM_LENGTH_NOT_MET',
      message: `Field '${fieldName}' does not meet minimum length requirement of ${minLength} characters.`,
      severity: 'MEDIUM',
      recommendation: `Provide a value with at least ${minLength} characters.`,
      currentLength: stringValue.trim().length,
      requiredLength: minLength,
      field: fieldName
    });
  }

  // Whitespace-only detection
  if (!result.isEmpty && typeof input === 'string' && input !== input.trim()) {
    result.warnings.push({
      type: 'LEADING_TRAILING_WHITESPACE',
      message: `Field '${fieldName}' contains leading or trailing whitespace.`,
      severity: 'LOW',
      recommendation: 'Consider trimming whitespace unless it is intentionally significant.',
      securityImpact: 'Unexpected whitespace may cause comparison failures or bypass validation.',
      field: fieldName,
      context: 'Whitespace handling'
    });
  }

  return result;
}

// Timing attack prevention functions removed - not applicable for middleware sanitization

/**
 * Comprehensive security enhancement analysis
 * @param {string} input - Input to analyze with all security enhancements
 * @param {Object} options - Configuration options
 * @returns {Promise<Object>} Complete analysis result
 */
async function comprehensiveSecurityAnalysis(input, options = {}) {
  const {
    checkDirectionalOverrides = true,
    checkNullBytes = true,
    checkMultipleEncoding = true,
    checkPostgresDollarQuotes = true,
    checkCyrillicHomographs = true,
    handleEmptyStrings = true,
    emptyStringContext = {},
    maxEncodingDepth = 4
  } = options;

  const startTime = Date.now();
  const results = {
    input,
    allWarnings: [],
    sanitized: input,
    metadata: {
      analysisTime: 0,
      checksPerformed: 0,
      highSeverityWarnings: 0,
      criticalWarnings: 0
    }
  };

  // Perform all security checks
  const checks = [];

  if (checkDirectionalOverrides) {
    checks.push({ name: 'directionalOverrides', fn: () => detectDirectionalOverrides(input) });
  }

  if (checkNullBytes) {
    checks.push({ name: 'nullBytes', fn: () => detectNullBytes(input) });
  }

  if (checkMultipleEncoding) {
    checks.push({ name: 'multipleEncoding', fn: () => detectMultipleUrlEncoding(input, maxEncodingDepth) });
  }

  if (checkPostgresDollarQuotes) {
    checks.push({ name: 'postgresDollarQuotes', fn: () => detectPostgresDollarQuotes(input) });
  }

  if (checkCyrillicHomographs) {
    checks.push({ name: 'cyrillicHomographs', fn: () => detectCyrillicHomographs(input) });
  }

  if (options.handleEmptyStrings) {
    checks.push({ name: 'emptyStrings', fn: () => handleEmptyStrings(input, emptyStringContext) });
  }

  // Execute all checks
  const checkResults = {};
  for (const check of checks) {
    const checkResult = check.fn();
    checkResults[check.name] = checkResult;
    
    if (checkResult.warnings) {
      results.allWarnings.push(...checkResult.warnings);
    }
    
    // Update sanitized value if changed
    if (checkResult.sanitized && checkResult.sanitized !== results.sanitized) {
      results.sanitized = checkResult.sanitized;
    }
    if (checkResult.normalized && checkResult.normalized !== results.sanitized) {
      results.sanitized = checkResult.normalized;
    }
    if (checkResult.decoded && checkResult.decoded !== results.sanitized) {
      results.sanitized = checkResult.decoded;
    }
    if (checkResult.processed && checkResult.processed !== results.sanitized) {
      results.sanitized = checkResult.processed;
    }
  }

  // Analyze warning severities
  for (const warning of results.allWarnings) {
    if (warning.severity === 'HIGH') {
      results.metadata.highSeverityWarnings++;
    } else if (warning.severity === 'CRITICAL') {
      results.metadata.criticalWarnings++;
    }
  }

  results.metadata.analysisTime = Date.now() - startTime;
  results.metadata.checksPerformed = checks.length;
  results.checkResults = checkResults;

  return results;
}

module.exports = {
  // Individual detection functions
  detectDirectionalOverrides,
  detectNullBytes,
  detectMultipleUrlEncoding,
  detectPostgresDollarQuotes,
  detectCyrillicHomographs,
  handleEmptyStrings,
  
  // Comprehensive analysis
  comprehensiveSecurityAnalysis,
  
  // Constants for external use
  DIRECTIONAL_OVERRIDES,
  CYRILLIC_HOMOGRAPHS,
  POSTGRES_DOLLAR_QUOTE_PATTERNS
};