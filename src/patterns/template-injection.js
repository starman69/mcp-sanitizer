/**
 * Template Injection Pattern Detection Module
 *
 * Detects patterns commonly used in template injection attacks, including
 * template literals, Server-Side Template Injection (SSTI), and various
 * template engine-specific attack vectors.
 *
 * Based on security best practices from OWASP template injection prevention,
 * and common attack patterns across different template engines.
 */

const SEVERITY_LEVELS = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low'
}

/**
 * Generic template injection patterns
 */
const GENERIC_TEMPLATE_PATTERNS = [
  // JavaScript template literals
  /\$\{.*?\}/g,
  /`.*?\$\{.*?\}.*?`/g,

  // Common template delimiters
  /\{\{.*?\}\}/g, // Handlebars, Angular, Vue
  /\{%.*?%\}/g, // Jinja2, Django, Twig
  /\{#.*?#\}/g, // Jinja2 comments
  /<%.*?%>/g, // EJS, ERB
  /\{@.*?@\}/g, // Dust.js
  /\{!.*?!\}/g, // Mustache comments

  // Expression patterns
  /\{\{[^}]*[+\-*/=<>!&|][^}]*\}\}/g, // Expressions in templates
  /\{%[^%]*[+\-*/=<>!&|][^%]*%\}/g,
  /<%[^%]*[+\-*/=<>!&|][^%]*%>/g
]

/**
 * Template engine specific patterns
 */
const TEMPLATE_ENGINE_PATTERNS = {
  jinja2: [
    // Jinja2 specific syntax
    /\{\{.*?config.*?\}\}/gi,
    /\{\{.*?request.*?\}\}/gi,
    /\{\{.*?self.*?\}\}/gi,
    /\{\{.*?\.__class__.*?\}\}/gi,
    /\{\{.*?\.__bases__.*?\}\}/gi,
    /\{\{.*?\.__subclasses__.*?\}\}/gi,
    /\{\{.*?\.__globals__.*?\}\}/gi,
    /\{\{.*?\.__builtins__.*?\}\}/gi,
    /\{\{.*?\.__import__.*?\}\}/gi,
    /\{%.*?import.*?%\}/gi,
    /\{%.*?from.*?import.*?%\}/gi,
    /\{\{.*?lipsum.*?\}\}/gi, // Jinja2 lipsum function
    /\{\{.*?cycler.*?\}\}/gi, // Jinja2 cycler function
    /\{\{.*?joiner.*?\}\}/gi // Jinja2 joiner function
  ],

  django: [
    // Django specific syntax
    /\{%.*?load.*?%\}/gi,
    /\{%.*?include.*?%\}/gi,
    /\{%.*?extends.*?%\}/gi,
    /\{\{.*?block.*?\}\}/gi,
    /\{%.*?block.*?%\}/gi,
    /\{\{.*?forloop.*?\}\}/gi,
    /\{\{.*?request\..*?\}\}/gi
  ],

  twig: [
    // Twig specific syntax
    /\{\{.*?_self.*?\}\}/gi,
    /\{\{.*?attribute.*?\}\}/gi,
    /\{\{.*?template_from_string.*?\}\}/gi,
    /\{%.*?sandbox.*?%\}/gi,
    /\{%.*?autoescape.*?%\}/gi,
    /\{\{.*?constant.*?\}\}/gi
  ],

  smarty: [
    // Smarty specific syntax
    /\{php\}.*?\{\/php\}/gi,
    /\{\$.*?\}/g,
    /\{literal\}.*?\{\/literal\}/gi,
    /\{eval.*?\}/gi,
    /\{include.*?\}/gi,
    /\{config_load.*?\}/gi
  ],

  freemarker: [
    // FreeMarker specific syntax
    /<#.*?>/g,
    /<@.*?>/g,
    /\$\{.*?\?.*?\}/g, // FreeMarker built-ins
    /<#assign.*?>/gi,
    /<#global.*?>/gi,
    /<#import.*?>/gi,
    /<#include.*?>/gi,
    /\$\{.*?\.class.*?\}/gi,
    /\$\{.*?\.getClass.*?\}/gi
  ],

  velocity: [
    // Velocity specific syntax
    /#set\s*\(/gi,
    /#if\s*\(/gi,
    /#foreach\s*\(/gi,
    /#macro\s*\(/gi,
    /#parse\s*\(/gi,
    /#include\s*\(/gi,
    /#evaluate\s*\(/gi,
    /\$\{.*?\.class.*?\}/gi,
    /\$\{.*?\.getClass.*?\}/gi
  ],

  thymeleaf: [
    // Thymeleaf specific syntax
    /th:[a-z]+\s*=/gi,
    /\[\[.*?\]\]/g,
    /\(\(.*?\)\)/g,
    /@\{.*?\}/g,
    /\$\{.*?\}/g,
    /\*\{.*?\}/g,
    /#\{.*?\}/g
  ],

  handlebars: [
    // Handlebars specific syntax
    /\{\{\{.*?\}\}\}/g, // Triple braces (unescaped)
    /\{\{#.*?\}\}/g, // Block helpers
    /\{\{\/.*?\}\}/g, // Closing block helpers
    /\{\{>.*?\}\}/g, // Partials
    /\{\{!.*?\}\}/g, // Comments
    /\{\{@.*?\}\}/g, // Data variables
    /\{\{.*?\.\.\/.*?\}\}/g // Parent context
  ]
}

/**
 * Server-Side Template Injection (SSTI) payload patterns
 */
const SSTI_PAYLOAD_PATTERNS = [
  // Python object introspection
  /__class__/gi,
  /__bases__/gi,
  /__subclasses__/gi,
  /__mro__/gi,
  /__globals__/gi,
  /__builtins__/gi,
  /__import__/gi,

  // Java reflection patterns
  /\.class\./gi,
  /\.getClass\(/gi,
  /\.forName\(/gi,
  /\.newInstance\(/gi,
  /\.getMethod\(/gi,
  /\.invoke\(/gi,

  // Ruby/Rails patterns
  /\.class\./gi,
  /\.ancestors/gi,
  /\.methods/gi,
  /\.send\(/gi,
  /\.eval\(/gi,
  /\.instance_eval\(/gi,
  /\.class_eval\(/gi,

  // PHP patterns
  /system\(/gi,
  /exec\(/gi,
  /passthru\(/gi,
  /shell_exec\(/gi,
  /popen\(/gi,
  /proc_open\(/gi,
  /file_get_contents\(/gi,
  /include\(/gi,
  /require\(/gi,

  // JavaScript patterns
  /constructor/gi,
  /prototype/gi,
  /eval\(/gi,
  /Function\(/gi,
  /setTimeout\(/gi,
  /setInterval\(/gi
]

/**
 * Expression language injection patterns
 */
const EXPRESSION_LANGUAGE_PATTERNS = [
  // Spring EL
  /T\(.*?\)/g, // Type references
  /@.*?\(/g, // Bean references
  /#.*?\(/g, // Variable references
  /\$\{.*?T\(.*?\).*?\}/g,

  // OGNL (Object-Graph Navigation Language)
  /@.*?@/g, // Static method calls
  /#.*?#/g, // Context variables
  /\(#.*?\)/g, // Variable assignment

  // MVEL
  /with\s*\(/gi,
  /import\s+/gi,
  /new\s+/gi,
  /\$\{.*?with\s*\(.*?\).*?\}/gi,

  // SpEL (Spring Expression Language)
  /#root/gi,
  /#this/gi,
  /systemProperties/gi,
  /systemEnvironment/gi
]

/**
 * Template code execution patterns
 */
const CODE_EXECUTION_PATTERNS = [
  // Direct code execution
  /eval\s*\(/gi,
  /exec\s*\(/gi,
  /system\s*\(/gi,
  /shell_exec\s*\(/gi,
  /passthru\s*\(/gi,
  /popen\s*\(/gi,
  /proc_open\s*\(/gi,

  // File operations
  /file_get_contents\s*\(/gi,
  /file_put_contents\s*\(/gi,
  /fopen\s*\(/gi,
  /fwrite\s*\(/gi,
  /include\s*\(/gi,
  /require\s*\(/gi,
  /include_once\s*\(/gi,
  /require_once\s*\(/gi,

  // Network operations
  /curl_exec\s*\(/gi,
  /file_get_contents\s*\(\s*['"]\s*https?:/gi,
  /fsockopen\s*\(/gi,
  /stream_context_create\s*\(/gi
]

/**
 * Main detection function for template injection patterns
 * @param {string} input - The input string to analyze
 * @param {Object} options - Detection options
 * @returns {Object} Detection result with severity and details
 */
function detectTemplateInjection (input, options = {}) {
  if (typeof input !== 'string') {
    return { detected: false, severity: null, patterns: [] }
  }

  const detectedPatterns = []
  let maxSeverity = null

  // Check generic template patterns
  const genericResult = checkGenericTemplatePatterns(input)
  if (genericResult.detected) {
    detectedPatterns.push(...genericResult.patterns)
    maxSeverity = getHigherSeverity(maxSeverity, genericResult.severity)
  }

  // Check template engine specific patterns
  const engineResult = checkTemplateEnginePatterns(input)
  if (engineResult.detected) {
    detectedPatterns.push(...engineResult.patterns)
    maxSeverity = getHigherSeverity(maxSeverity, engineResult.severity)
  }

  // Check SSTI payload patterns
  const sstiResult = checkSSTIPayloadPatterns(input)
  if (sstiResult.detected) {
    detectedPatterns.push(...sstiResult.patterns)
    maxSeverity = getHigherSeverity(maxSeverity, sstiResult.severity)
  }

  // Check expression language patterns
  const expressionResult = checkExpressionLanguagePatterns(input)
  if (expressionResult.detected) {
    detectedPatterns.push(...expressionResult.patterns)
    maxSeverity = getHigherSeverity(maxSeverity, expressionResult.severity)
  }

  // Check code execution patterns
  const codeExecResult = checkCodeExecutionPatterns(input)
  if (codeExecResult.detected) {
    detectedPatterns.push(...codeExecResult.patterns)
    maxSeverity = getHigherSeverity(maxSeverity, codeExecResult.severity)
  }

  return {
    detected: detectedPatterns.length > 0,
    severity: maxSeverity,
    patterns: detectedPatterns,
    message: detectedPatterns.length > 0
      ? `Template injection patterns detected: ${detectedPatterns.join(', ')}`
      : null
  }
}

/**
 * Check for generic template patterns
 */
function checkGenericTemplatePatterns (input) {
  const detected = []

  for (const pattern of GENERIC_TEMPLATE_PATTERNS) {
    if (pattern.test(input)) {
      detected.push(`generic_template:${pattern.source}`)
    }
  }

  return {
    detected: detected.length > 0,
    severity: detected.length > 0 ? SEVERITY_LEVELS.MEDIUM : null,
    patterns: detected
  }
}

/**
 * Check for template engine specific patterns
 */
function checkTemplateEnginePatterns (input) {
  const detected = []

  for (const [engine, patterns] of Object.entries(TEMPLATE_ENGINE_PATTERNS)) {
    for (const pattern of patterns) {
      if (pattern.test(input)) {
        detected.push(`${engine}_template:${pattern.source}`)
      }
    }
  }

  return {
    detected: detected.length > 0,
    severity: detected.length > 0 ? SEVERITY_LEVELS.HIGH : null,
    patterns: detected
  }
}

/**
 * Check for SSTI payload patterns
 */
function checkSSTIPayloadPatterns (input) {
  const detected = []

  for (const pattern of SSTI_PAYLOAD_PATTERNS) {
    if (pattern.test(input)) {
      detected.push(`ssti_payload:${pattern.source}`)
    }
  }

  return {
    detected: detected.length > 0,
    severity: detected.length > 0 ? SEVERITY_LEVELS.CRITICAL : null,
    patterns: detected
  }
}

/**
 * Check for expression language patterns
 */
function checkExpressionLanguagePatterns (input) {
  const detected = []

  for (const pattern of EXPRESSION_LANGUAGE_PATTERNS) {
    if (pattern.test(input)) {
      detected.push(`expression_language:${pattern.source}`)
    }
  }

  return {
    detected: detected.length > 0,
    severity: detected.length > 0 ? SEVERITY_LEVELS.HIGH : null,
    patterns: detected
  }
}

/**
 * Check for code execution patterns
 */
function checkCodeExecutionPatterns (input) {
  const detected = []

  for (const pattern of CODE_EXECUTION_PATTERNS) {
    if (pattern.test(input)) {
      detected.push(`code_execution:${pattern.source}`)
    }
  }

  return {
    detected: detected.length > 0,
    severity: detected.length > 0 ? SEVERITY_LEVELS.CRITICAL : null,
    patterns: detected
  }
}

/**
 * Get the higher severity between two severity levels
 */
function getHigherSeverity (current, newSeverity) {
  if (!current) return newSeverity
  if (!newSeverity) return current

  const severityOrder = [
    SEVERITY_LEVELS.LOW,
    SEVERITY_LEVELS.MEDIUM,
    SEVERITY_LEVELS.HIGH,
    SEVERITY_LEVELS.CRITICAL
  ]

  const currentIndex = severityOrder.indexOf(current)
  const newIndex = severityOrder.indexOf(newSeverity)

  return newIndex > currentIndex ? newSeverity : current
}

/**
 * Simple boolean check for template injection
 * @param {string} input - The input string to check
 * @returns {boolean} True if template injection patterns are detected
 */
function isTemplateInjection (input) {
  return detectTemplateInjection(input).detected
}

module.exports = {
  // Main detection functions
  detectTemplateInjection,
  isTemplateInjection,

  // Individual checkers
  checkGenericTemplatePatterns,
  checkTemplateEnginePatterns,
  checkSSTIPayloadPatterns,
  checkExpressionLanguagePatterns,
  checkCodeExecutionPatterns,

  // Pattern exports for reuse
  GENERIC_TEMPLATE_PATTERNS,
  TEMPLATE_ENGINE_PATTERNS,
  SSTI_PAYLOAD_PATTERNS,
  EXPRESSION_LANGUAGE_PATTERNS,
  CODE_EXECUTION_PATTERNS,

  // Constants
  SEVERITY_LEVELS
}
