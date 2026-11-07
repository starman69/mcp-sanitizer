/**
 * Enterprise Security Enhancements Module
 *
 * Provides advanced security detection and sanitization for inline use
 * Focus: Maximum security with minimal latency (<10ms)
 * Scope: Inline sanitization library (not edge/network)
 */

const { testRegex } = require('./redos-safe-patterns');

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
function detectDirectionalOverride (input) {
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
    if (input.match(/[\u202E][^\n]{0,500}\/(etc|usr|bin|var|sys|proc)/)) {
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
function detectNullBytes (input) {
  if (typeof input !== 'string') {
    return { detected: false, warnings: [] };
  }

  const warnings = [];
  let detected = false;

  // Check for literal null bytes
  if (input.includes('\x00')) {
    detected = true;
    // eslint-disable-next-line no-control-regex
    const count = (input.match(/\x00/g) || []).length;
    warnings.push(`Null byte injection detected: ${count} null byte(s) found`);
    warnings.push('Security: Null bytes can terminate strings in C-based systems');

    // Check context
    // eslint-disable-next-line no-control-regex
    if (input.match(/\.(txt|log|conf|ini)\x00/)) {
      warnings.push('Critical: Null byte attempting to bypass file extension checks');
    }

    // eslint-disable-next-line no-control-regex
    if (input.match(/\/etc\/[^\x00]{0,500}\x00/)) {
      warnings.push('Critical: Null byte in system path - potential path traversal');
    }
  }

  // Check for other dangerous control characters
  // eslint-disable-next-line no-control-regex
  const controlChars = input.match(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g);
  if (controlChars) {
    warnings.push(`Control characters detected: ${controlChars.length} dangerous character(s)`);
  }

  return {
    detected,
    warnings,
    // eslint-disable-next-line no-control-regex
    sanitized: input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
  };
}

/**
 * Detect multi-layer URL encoding attempts
 * @param {string} input - Input to check
 * @param {number} maxDepth - Maximum decode depth (default 5)
 * @returns {Object} Detection result
 */
function detectDoubleEncoding (input, maxDepth = 5) {
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
function detectPostgreSQLDollarQuoting (input) {
  if (typeof input !== 'string') {
    return { detected: false, warnings: [] };
  }

  const warnings = [];
  let detected = false;

  // Pattern for dollar quoting: $$ or $tag$
  const dollarQuotePattern = /\$([a-zA-Z_][a-zA-Z0-9_]*)?\$[^$]{0,10000}\$\1\$/g;
  const simpleDollarPattern = /\$\$[^$]{0,10000}\$\$/g;

  if (testRegex(dollarQuotePattern, input) || testRegex(simpleDollarPattern, input)) {
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

// Comprehensive confusable character mappings for homograph detection
const CONFUSABLE_MAPPINGS = {
  // Fullwidth characters (commonly used in homograph attacks)
  ａ: 'a',
  ｂ: 'b',
  ｃ: 'c',
  ｄ: 'd',
  ｅ: 'e',
  ｆ: 'f',
  ｇ: 'g',
  ｈ: 'h',
  ｉ: 'i',
  ｊ: 'j',
  ｋ: 'k',
  ｌ: 'l',
  ｍ: 'm',
  ｎ: 'n',
  ｏ: 'o',
  ｐ: 'p',
  ｑ: 'q',
  ｒ: 'r',
  ｓ: 's',
  ｔ: 't',
  ｕ: 'u',
  ｖ: 'v',
  ｗ: 'w',
  ｘ: 'x',
  ｙ: 'y',
  ｚ: 'z',
  Ａ: 'A',
  Ｂ: 'B',
  Ｃ: 'C',
  Ｄ: 'D',
  Ｅ: 'E',
  Ｆ: 'F',
  Ｇ: 'G',
  Ｈ: 'H',
  Ｉ: 'I',
  Ｊ: 'J',
  Ｋ: 'K',
  Ｌ: 'L',
  Ｍ: 'M',
  Ｎ: 'N',
  Ｏ: 'O',
  Ｐ: 'P',
  Ｑ: 'Q',
  Ｒ: 'R',
  Ｓ: 'S',
  Ｔ: 'T',
  Ｕ: 'U',
  Ｖ: 'V',
  Ｗ: 'W',
  Ｘ: 'X',
  Ｙ: 'Y',
  Ｚ: 'Z',
  '０': '0',
  '１': '1',
  '２': '2',
  '３': '3',
  '４': '4',
  '５': '5',
  '６': '6',
  '７': '7',
  '８': '8',
  '９': '9',

  // Fullwidth punctuation and symbols
  '！': '!',
  '＂': '"',
  '＃': '#',
  '＄': '$',
  '％': '%',
  '＆': '&',
  '＇': "'",
  '（': '(',
  '）': ')',
  '＊': '*',
  '＋': '+',
  '，': ',',
  '－': '-',
  // '．': '.', // Duplicate - already defined above
  '／': '/',
  '：': ':',
  '；': ';',
  '＜': '<',
  '＝': '=',
  '＞': '>',
  '？': '?',
  '＠': '@',
  '［': '[',
  '＼': '\\',
  '］': ']',
  '＾': '^',
  '＿': '_',
  '｀': '`',
  '｛': '{',
  '｜': '|',
  '｝': '}',
  '～': '~',

  // Cyrillic lookalikes (extended coverage)
  а: 'a',
  е: 'e',
  о: 'o',
  р: 'p',
  с: 'c',
  у: 'y',
  х: 'x',
  ь: 'b',
  і: 'i',
  ј: 'j',
  А: 'A',
  В: 'B',
  Е: 'E',
  К: 'K',
  М: 'M',
  Н: 'H',
  О: 'O',
  Р: 'P',
  С: 'C',
  Т: 'T',
  У: 'Y',
  Х: 'X',
  Ѕ: 'S',
  І: 'I',
  Ј: 'J',
  ѓ: 'r',
  ѕ: 's',
  ќ: 'k',
  ї: 'i',
  љ: 'h',
  њ: 'h',
  ћ: 'h',
  џ: 'u',

  // Greek lookalikes
  α: 'a',
  β: 'B',
  γ: 'y',
  δ: 'o',
  ε: 'e',
  ζ: 'z',
  η: 'n',
  θ: 'o',
  ι: 'i',
  κ: 'k',
  λ: 'A',
  μ: 'u',
  ν: 'v',
  ξ: 'E',
  ο: 'o',
  π: 'n',
  ρ: 'p',
  σ: 'o',
  τ: 't',
  υ: 'u',
  φ: 'o',
  χ: 'x',
  ψ: 'w',
  ω: 'w',
  Α: 'A',
  Β: 'B',
  Γ: 'r',
  Δ: 'A',
  Ε: 'E',
  Ζ: 'Z',
  Η: 'H',
  Θ: 'O',
  Ι: 'I',
  Κ: 'K',
  Λ: 'A',
  Μ: 'M',
  Ν: 'N',
  Ξ: 'E',
  Ο: 'O',
  Π: 'n',
  Ρ: 'P',
  Σ: 'E',
  Τ: 'T',
  Υ: 'Y',
  Φ: 'O',
  Χ: 'X',
  Ψ: 'W',
  Ω: 'O',

  // Mathematical alphanumeric symbols - Bold
  '𝐚': 'a',
  '𝐛': 'b',
  '𝐜': 'c',
  '𝐝': 'd',
  '𝐞': 'e',
  '𝐟': 'f',
  '𝐠': 'g',
  '𝐡': 'h',
  '𝐢': 'i',
  '𝐣': 'j',
  '𝐤': 'k',
  '𝐥': 'l',
  '𝐦': 'm',
  '𝐧': 'n',
  '𝐨': 'o',
  '𝐩': 'p',
  '𝐪': 'q',
  '𝐫': 'r',
  '𝐬': 's',
  '𝐭': 't',
  '𝐮': 'u',
  '𝐯': 'v',
  '𝐰': 'w',
  '𝐱': 'x',
  '𝐲': 'y',
  '𝐳': 'z',
  '𝐀': 'A',
  '𝐁': 'B',
  '𝐂': 'C',
  '𝐃': 'D',
  '𝐄': 'E',
  '𝐅': 'F',
  '𝐆': 'G',
  '𝐇': 'H',
  '𝐈': 'I',
  '𝐉': 'J',
  '𝐊': 'K',
  '𝐋': 'L',
  '𝐌': 'M',
  '𝐍': 'N',
  '𝐎': 'O',
  '𝐏': 'P',
  '𝐐': 'Q',
  '𝐑': 'R',
  '𝐒': 'S',
  '𝐓': 'T',
  '𝐔': 'U',
  '𝐕': 'V',
  '𝐖': 'W',
  '𝐗': 'X',
  '𝐘': 'Y',
  '𝐙': 'Z',

  // Mathematical alphanumeric symbols - Italic
  '𝑎': 'a',
  '𝑏': 'b',
  '𝑐': 'c',
  '𝑑': 'd',
  '𝑒': 'e',
  '𝑓': 'f',
  '𝑔': 'g',
  '𝒉': 'h',
  '𝑖': 'i',
  '𝑗': 'j',
  '𝑘': 'k',
  '𝑙': 'l',
  '𝑚': 'm',
  '𝑛': 'n',
  '𝑜': 'o',
  '𝑝': 'p',
  '𝑞': 'q',
  '𝑟': 'r',
  '𝑠': 's',
  '𝑡': 't',
  '𝑢': 'u',
  '𝑣': 'v',
  '𝑤': 'w',
  '𝑥': 'x',
  '𝑦': 'y',
  '𝑧': 'z',
  '𝐴': 'A',
  '𝐵': 'B',
  '𝐶': 'C',
  '𝐷': 'D',
  '𝐸': 'E',
  '𝐹': 'F',
  '𝐺': 'G',
  '𝐻': 'H',
  '𝐼': 'I',
  '𝐽': 'J',
  '𝐾': 'K',
  '𝐿': 'L',
  '𝑀': 'M',
  '𝑁': 'N',
  '𝑂': 'O',
  '𝑃': 'P',
  '𝑄': 'Q',
  '𝑅': 'R',
  '𝑆': 'S',
  '𝑇': 'T',
  '𝑈': 'U',
  '𝑉': 'V',
  '𝑊': 'W',
  '𝑋': 'X',
  '𝑌': 'Y',
  '𝑍': 'Z',

  // Mathematical script/calligraphic symbols
  '𝒂': 'a',
  '𝒃': 'b',
  '𝒸': 'c',
  '𝒹': 'd',
  '𝒅': 'd',
  '𝒆': 'e',
  '𝒇': 'f',
  '𝒈': 'g',
  // '𝒉': 'h', // Duplicate - already defined above
  '𝒊': 'i',
  '𝒋': 'j',
  '𝒌': 'k',
  '𝒍': 'l',
  '𝒎': 'm',
  '𝒏': 'n',
  '𝒐': 'o',
  '𝒑': 'p',
  '𝒒': 'q',
  '𝒓': 'r',
  '𝒔': 's',
  '𝒕': 't',
  '𝒖': 'u',
  '𝒗': 'v',
  '𝒘': 'w',
  '𝒙': 'x',
  '𝒚': 'y',
  '𝒛': 'z',
  // Mathematical bold script lowercase
  '𝓪': 'a',
  '𝓫': 'b',
  '𝓬': 'c',
  '𝓭': 'd',
  '𝓮': 'e',
  '𝓯': 'f',
  '𝓰': 'g',
  '𝓱': 'h',
  '𝓲': 'i',
  '𝓳': 'j',
  '𝓴': 'k',
  '𝓵': 'l',
  '𝓶': 'm',
  '𝓷': 'n',
  '𝓸': 'o',
  '𝓹': 'p',
  '𝓺': 'q',
  '𝓻': 'r',
  '𝓼': 's',
  '𝓽': 't',
  '𝓾': 'u',
  '𝓿': 'v',
  '𝔀': 'w',
  '𝔁': 'x',
  '𝔂': 'y',
  '𝔃': 'z',
  // Mathematical bold script uppercase
  '𝓐': 'A',
  '𝓑': 'B',
  '𝓒': 'C',
  '𝓓': 'D',
  '𝓔': 'E',
  '𝓕': 'F',
  '𝓖': 'G',
  '𝓗': 'H',
  '𝓘': 'I',
  '𝓙': 'J',
  '𝓚': 'K',
  '𝓛': 'L',
  '𝓜': 'M',
  '𝓝': 'N',
  '𝓞': 'O',
  '𝓟': 'P',
  '𝓠': 'Q',
  '𝓡': 'R',
  '𝓢': 'S',
  '𝓣': 'T',
  '𝓤': 'U',
  '𝓥': 'V',
  '𝓦': 'W',
  '𝓧': 'X',
  '𝓨': 'Y',
  '𝓩': 'Z',

  // Mathematical digits
  '𝟎': '0',
  '𝟏': '1',
  '𝟐': '2',
  '𝟑': '3',
  '𝟒': '4',
  '𝟓': '5',
  '𝟔': '6',
  '𝟕': '7',
  '𝟖': '8',
  '𝟗': '9',
  '𝟘': '0',
  '𝟙': '1',
  '𝟚': '2',
  '𝟛': '3',
  '𝟜': '4',
  '𝟝': '5',
  '𝟞': '6',
  '𝟟': '7',
  '𝟠': '8',
  '𝟡': '9',
  '𝟢': '0',
  '𝟣': '1',
  '𝟤': '2',
  '𝟥': '3',
  '𝟦': '4',
  '𝟧': '5',
  '𝟨': '6',
  '𝟩': '7',
  '𝟪': '8',
  '𝟫': '9',

  // Additional common lookalikes and spacing
  '‒': '-',
  '–': '-',
  '—': '-',
  '―': '-',
  '−': '-',
  '⁻': '-',
  '\u2018': "'",
  '\u2019': "'",
  '\u201A': "'",
  '\u201B': "'",
  '\u201C': '"',
  '\u201D': '"',
  '\u201E': '"',
  '\u201F': '"',
  '⁄': '/',
  '∕': '/',
  '⧸': '/',
  '⸼': ':',
  '︰': ':',
  ː: ':',
  '．': '.',
  '｡': '.',
  '︒': '.',
  '　': ' ' // Fullwidth space to regular space
};

// Zero-width and invisible character patterns
const ZERO_WIDTH_CHARS = {
  ZWSP: '\u200B', // Zero Width Space
  ZWNJ: '\u200C', // Zero Width Non-Joiner
  ZWJ: '\u200D', // Zero Width Joiner
  ZWNO: '\u200E', // Left-to-Right Mark
  RLM: '\u200F', // Right-to-Left Mark
  WJ: '\u2060', // Word Joiner
  FVSP: '\u2064', // Invisible Plus
  ISS: '\u2069', // Pop Directional Isolate
  BOM: '\uFEFF' // Byte Order Mark
};

// eslint-disable-next-line no-misleading-character-class
const ZERO_WIDTH_PATTERN = /[\u200B-\u200F\u2060\u2064\u2069\uFEFF]/g;

// Character type detection patterns
const CHARACTER_PATTERNS = {
  fullwidth: /[\uFF01-\uFFEF]/,
  // eslint-disable-next-line no-misleading-character-class
  cyrillic: /[\u0400-\u04FF\u0500-\u052F\u2DE0-\u2DFF\uA640-\uA69F]/,
  greek: /[\u0370-\u03FF\u1F00-\u1FFF]/,
  mathematical: /[\uD835][\uDC00-\uDFFF]/,
  arabic: /[\u0600-\u06FF\u0750-\u077F]/,
  hebrew: /[\u0590-\u05FF]/,
  // Emoji and symbol ranges (to exclude from homograph detection)
  emoji: /[\u{1F000}-\u{1F9FF}]|[\u{2600}-\u{26FF}]|[\u{2700}-\u{27BF}]|[\u{1F300}-\u{1F5FF}]|[\u{1F600}-\u{1F64F}]|[\u{1F680}-\u{1F6FF}]|[\u{1F700}-\u{1F77F}]|[\u{1F780}-\u{1F7FF}]|[\u{1F800}-\u{1F8FF}]|[\u{1F900}-\u{1F9FF}]|[\u{1FA00}-\u{1FA6F}]|[\u{1FA70}-\u{1FAFF}]/u,
  cjk: /[\u4E00-\u9FFF]|[\u3400-\u4DBF]|[\u{20000}-\u{2A6DF}]|[\u{2A700}-\u{2B73F}]|[\u{2B740}-\u{2B81F}]|[\u{2B820}-\u{2CEAF}]|[\u{2CEB0}-\u{2EBEF}]|[\u{30000}-\u{3134F}]/u
};

/**
 * Normalize confusable characters to their basic Latin equivalents
 * @param {string} input - Input string to normalize
 * @returns {string} Normalized string
 */
function normalizeConfusableChars (input) {
  if (typeof input !== 'string') {
    return input;
  }

  let normalized = input;

  // Apply confusable character mappings
  for (const [confusable, replacement] of Object.entries(CONFUSABLE_MAPPINGS)) {
    normalized = normalized.replace(new RegExp(confusable, 'g'), replacement);
  }

  // Remove zero-width and invisible characters
  normalized = normalized.replace(ZERO_WIDTH_PATTERN, '');

  return normalized;
}

/**
 * Perform multi-pass normalization to catch nested homographs
 * @param {string} input - Input to normalize
 * @param {number} maxPasses - Maximum normalization passes
 * @returns {Object} Normalization result
 */
function multiPassNormalization (input, maxPasses = 5) {
  if (typeof input !== 'string') {
    return { normalized: input, passes: 0, changes: [] };
  }

  let current = input;
  let previous = '';
  let passes = 0;
  const changes = [];

  while (current !== previous && passes < maxPasses) {
    previous = current;
    const beforeNorm = current;

    // Apply Unicode NFC normalization first
    current = current.normalize('NFC');

    // Apply confusable character normalization
    current = normalizeConfusableChars(current);

    passes++;

    if (beforeNorm !== current) {
      changes.push({
        pass: passes,
        before: beforeNorm,
        after: current,
        changesDetected: beforeNorm.length !== current.length || beforeNorm !== current
      });
    }
  }

  return {
    normalized: current,
    passes,
    changes,
    converged: current === previous,
    suspicious: passes >= 3 || changes.length > 2
  };
}

/**
 * Detect IDN homograph attacks in domains
 * @param {string} input - Domain or URL to check
 * @returns {Object} Detection result
 */
function detectIDNHomograph (input) {
  if (typeof input !== 'string') {
    return { detected: false, warnings: [] };
  }

  const warnings = [];
  let detected = false;

  // Extract domain from URL if needed
  let domain = input;
  try {
    if (input.includes('://')) {
      domain = new URL(input).hostname;
    } else if (input.includes('/')) {
      domain = input.split('/')[0];
    }
  } catch (e) {
    // Keep original input if URL parsing fails
  }

  const normalized = normalizeConfusableChars(domain.toLowerCase());

  // Check if normalization changed the domain
  if (domain.toLowerCase() !== normalized) {
    detected = true;
    warnings.push('IDN homograph attack detected: domain contains confusable characters');

    // Check against known high-value targets
    const knownDomains = ['google', 'facebook', 'microsoft', 'apple', 'amazon', 'github', 'paypal', 'twitter'];
    for (const knownDomain of knownDomains) {
      if (normalized.includes(knownDomain) && !domain.toLowerCase().includes(knownDomain)) {
        warnings.push(`Critical: Potential spoofing of ${knownDomain}.com domain`);
        break;
      }
    }
  }

  return {
    detected,
    warnings,
    originalDomain: domain,
    normalizedDomain: normalized
  };
}

/**
 * Comprehensive homograph detection with enhanced analysis
 * @param {string} input - Input to check
 * @param {Object} options - Detection options
 * @returns {Object} Detection result
 */
function detectHomographs (input, options = {}) {
  if (typeof input !== 'string') {
    return { detected: false, warnings: [], metadata: {} };
  }

  const {
    checkIDN = true,
    multiPass = true,
    detectZeroWidth = true
    // strictMode = false // Unused
  } = options;

  const warnings = [];
  const metadata = {
    characterTypes: [],
    confusableChars: [],
    zeroWidthChars: [],
    suspiciousPatterns: [],
    normalizationPasses: 0
  };

  // Perform multi-pass normalization
  const normResult = multiPass
    ? multiPassNormalization(input)
    : { normalized: normalizeConfusableChars(input), passes: 1, changes: [] };

  const normalized = normResult.normalized;
  let detected = input !== normalized;

  // Track normalization passes
  metadata.normalizationPasses = normResult.passes;

  // Skip detection for legitimate Unicode content
  const isLegitimateUnicode = testRegex(CHARACTER_PATTERNS.emoji, input) ||
                             testRegex(CHARACTER_PATTERNS.cjk, input);

  if (detected && !isLegitimateUnicode) {
    warnings.push('Unicode homograph attack detected: confusable characters present');

    // Analyze character types present
    if (testRegex(CHARACTER_PATTERNS.fullwidth, input)) {
      metadata.characterTypes.push('fullwidth');
      warnings.push('Fullwidth characters detected: potential spoofing attempt');
    }

    if (testRegex(CHARACTER_PATTERNS.cyrillic, input)) {
      metadata.characterTypes.push('cyrillic');
      warnings.push('Cyrillic homographs detected: characters visually similar to Latin');
    }

    if (testRegex(CHARACTER_PATTERNS.greek, input)) {
      metadata.characterTypes.push('greek');
      warnings.push('Greek homographs detected: potential visual spoofing');
    }

    if (testRegex(CHARACTER_PATTERNS.mathematical, input)) {
      metadata.characterTypes.push('mathematical');
      warnings.push('Mathematical alphanumeric symbols detected: Unicode lookalikes');
    }

    // Detect specific confusable characters
    for (const [confusable, replacement] of Object.entries(CONFUSABLE_MAPPINGS)) {
      if (input.includes(confusable)) {
        metadata.confusableChars.push({
          character: confusable,
          replacement,
          codePoint: `U+${confusable.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}`
        });
      }
    }
  }

  // Check for zero-width characters (always check, even for legitimate content)
  if (detectZeroWidth) {
    for (const [name, char] of Object.entries(ZERO_WIDTH_CHARS)) {
      if (input.includes(char)) {
        detected = true;
        metadata.zeroWidthChars.push({
          name,
          character: char,
          codePoint: `U+${char.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}`
        });
        warnings.push(`Zero-width character detected: ${name} (${metadata.zeroWidthChars[metadata.zeroWidthChars.length - 1].codePoint})`);
      }
    }
  }

  // Check for sensitive command spoofing
  if (normalized.match(/^(cat|ls|rm|echo|wget|curl|chmod|sudo|admin|password|login)/)) {
    warnings.push('Critical: Homograph attempting to spoof sensitive term');
    metadata.suspiciousPatterns.push('sensitive_command_spoofing');
  }

  // IDN homograph detection for domains
  if (checkIDN && (input.includes('.') || input.includes('://'))) {
    const idnResult = detectIDNHomograph(input);
    if (idnResult.detected) {
      detected = true;
      warnings.push(...idnResult.warnings);
      metadata.idnAnalysis = idnResult;
    }
  }

  // Multi-pass normalization warnings
  if (multiPass && normResult.suspicious) {
    warnings.push('Suspicious: Multiple normalization passes required');
    metadata.normalizationPasses = normResult.passes;
    metadata.normalizationChanges = normResult.changes;
  }

  return {
    detected,
    warnings,
    normalized,
    metadata,
    severity: detected ? (warnings.some(w => w.includes('Critical')) ? 'CRITICAL' : 'HIGH') : 'LOW'
  };
}

/**
 * Handle empty and whitespace-only strings appropriately
 * @param {*} input - Input to check
 * @param {Object} context - Sanitization context
 * @returns {Object} Handling result
 */
function handleEmptyInput (input, context = {}) {
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
 * Comprehensive security check combining all detections
 * @param {string} input - Input to check
 * @param {Object} options - Detection options
 * @returns {Object} Comprehensive security result
 */
function performSecurityChecks (input, options = {}) {
  const {
    checkDirectional = true,
    checkNullBytes = true,
    checkDoubleEncoding = true,
    checkHomographs = true
    // normalized = input // Unused
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

  // Enhanced homograph check with comprehensive Unicode analysis
  if (checkHomographs) {
    const homographResult = detectHomographs(input, {
      checkIDN: true,
      multiPass: true,
      detectZeroWidth: true,
      strictMode: false
    });
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

  // Enhanced Unicode detection functions
  normalizeConfusableChars,
  multiPassNormalization,
  detectIDNHomograph,

  // Comprehensive check
  performSecurityChecks,

  // Constants
  DIRECTIONAL_CHARS,
  DIRECTIONAL_PATTERN,
  CONFUSABLE_MAPPINGS,
  ZERO_WIDTH_CHARS,
  ZERO_WIDTH_PATTERN,
  CHARACTER_PATTERNS
};
