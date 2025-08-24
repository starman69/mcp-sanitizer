/**
 * SQL Injection Pattern Detection Module
 *
 * Detects patterns commonly used in SQL injection attacks, including
 * SQL keywords, union selects, comment attacks, and blind injection techniques.
 *
 * Based on security best practices from OWASP SQL Injection Prevention,
 * common SQL injection vectors, and database-specific attack patterns.
 */

const SEVERITY_LEVELS = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low'
};

/**
 * SQL keywords that are commonly used in injection attacks
 */
const SQL_KEYWORDS = [
  // Data manipulation
  /\b(DROP|DELETE|INSERT|UPDATE|CREATE|ALTER|TRUNCATE)\b/gi,

  // Data definition
  /\b(DATABASE|TABLE|INDEX|VIEW|PROCEDURE|FUNCTION|TRIGGER)\b/gi,

  // Access control
  /\b(GRANT|REVOKE|DENY)\b/gi,

  // System commands
  /\b(EXEC|EXECUTE|SHUTDOWN|BACKUP|RESTORE)\b/gi
];

/**
 * SQL injection attack patterns
 */
const INJECTION_PATTERNS = [
  // Union-based attacks
  /\bUNION\s+(ALL\s+)?SELECT\b/gi,
  /\bUNION\s+.*\bFROM\b/gi,

  // Boolean-based blind injection
  /\b(AND|OR)\s+\d+\s*[=<>!]+\s*\d+/gi,
  /\b(AND|OR)\s+['"]?\w+['"]?\s*[=<>!]+\s*['"]?\w+['"]?/gi,
  /\b(AND|OR)\s+\d+\s*BETWEEN\s+\d+\s+AND\s+\d+/gi,

  // Time-based blind injection
  /\bWAITFOR\s+DELAY\s+['"]\d+:\d+:\d+['"]/gi,
  /\bSLEEP\s*\(\s*\d+\s*\)/gi,
  /\bBENCHMARK\s*\(\s*\d+\s*,/gi,
  /\bpg_sleep\s*\(\s*\d+\s*\)/gi,

  // Error-based injection
  /\bCONVERT\s*\(\s*int\s*,/gi,
  /\bCAST\s*\(\s*\w+\s+AS\s+int\s*\)/gi,
  /\bEXTRACTVALUE\s*\(/gi,
  /\bUPDATEXML\s*\(/gi,

  // Stacked queries
  /;\s*(INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)/gi,
  /;\s*--/,
  /;\s*\/\*/
];

/**
 * SQL comment patterns used to bypass filters
 */
const COMMENT_PATTERNS = [
  /--\s*.*$/gm, // SQL line comments
  /\/\*[\s\S]*?\*\//g, // SQL block comments
  /\/\*.*$/gm, // Unclosed block comments
  /#.*$/gm, // MySQL comments
  /--\+.*$/gm, // Oracle hints
  /\/\*!\d+.*?\*\//g // MySQL version-specific comments
];

/**
 * Database-specific injection patterns
 */
const DATABASE_SPECIFIC_PATTERNS = {
  mysql: [
    /\bINTO\s+OUTFILE\b/gi, // File operations
    /\bLOAD_FILE\s*\(/gi,
    /\bINTO\s+DUMPFILE\b/gi,
    /\bINFORMATION_SCHEMA\b/gi, // Schema enumeration
    /\bMYSQL\b.*\bUSER\b/gi,
    /\bVERSION\s*\(\s*\)/gi,
    /\bDATABASE\s*\(\s*\)/gi,
    /\bUSER\s*\(\s*\)/gi
  ],

  postgresql: [
    /\bCOPY\s+.*\bTO\s+PROGRAM\b/gi, // Command execution
    /\bpg_read_file\s*\(/gi, // File operations
    /\bpg_ls_dir\s*\(/gi,
    /\bCURRENT_DATABASE\s*\(\s*\)/gi, // Schema enumeration
    /\bCURRENT_USER\s*\(\s*\)/gi,
    /\bVERSION\s*\(\s*\)/gi,
    /\bpg_sleep\s*\(/gi, // Time delays
    /\$\$[^$]*\$\$/g, // Dollar quoting ($$...$$)
    /\$([a-zA-Z_][a-zA-Z0-9_]*)\$[^$]*\$\1\$/g // Tagged dollar quotes ($tag$...$tag$)
  ],

  mssql: [
    /\bxp_cmdshell\b/gi, // Command execution
    /\bsp_OACreate\b/gi,
    /\bsp_OAMethod\b/gi,
    /\bOPENROWSET\s*\(/gi, // Linked servers
    /\bOPENDATASOURCE\s*\(/gi,
    /\bSYS\.DATABASES\b/gi, // Schema enumeration
    /\bSYS\.TABLES\b/gi,
    /\bSYSTEM_USER\b/gi,
    /\bSUSER_SNAME\s*\(\s*\)/gi
  ],

  oracle: [
    /\bUTL_FILE\b/gi, // File operations
    /\bUTL_HTTP\b/gi,
    /\bDBMS_XMLQUERY\b/gi, // XML operations
    /\bDBMS_XMLGEN\b/gi,
    /\bALL_TABLES\b/gi, // Schema enumeration
    /\bALL_TAB_COLUMNS\b/gi,
    /\bUSER_TABLES\b/gi,
    /\bSYS\.USER_OBJECTS\b/gi
  ],

  sqlite: [
    /\bsqlite_master\b/gi, // Schema enumeration
    /\bsqlite_temp_master\b/gi,
    /\bPRAGMA\s+table_info\s*\(/gi,
    /\bPRAGMA\s+database_list\b/gi,
    /\bATTACH\s+DATABASE\b/gi // Database manipulation
  ]
};

/**
 * Encoded SQL injection patterns
 */
const ENCODED_PATTERNS = [
  /0x[0-9a-f]+/gi, // Hex encoding
  /CHAR\s*\(\s*\d+\s*\)/gi, // CHAR function encoding
  /CHR\s*\(\s*\d+\s*\)/gi, // CHR function encoding
  /ASCII\s*\(\s*\d+\s*\)/gi, // ASCII function
  /CONCAT\s*\(/gi, // String concatenation
  /\|\|/g, // String concatenation (Oracle/PostgreSQL)
  /\+.*\+/g // String concatenation (SQL Server)
];

/**
 * Bypass techniques
 */
const BYPASS_PATTERNS = [
  /\s+/g, // Multiple spaces
  /\/\*.*?\*\//g, // Inline comments
  /\bunion\s*\/\*.*?\*\//gi, // Comment-separated keywords
  /\bselect\s*\/\*.*?\*\//gi,
  /['"]\s*\+\s*['"]/g, // Quote concatenation
  /['"]\s*\|\|\s*['"]/g, // Quote concatenation (Oracle/PostgreSQL)
  /\b\w+\s*\(\s*\)/g // Function calls without parameters
];

/**
 * Main detection function for SQL injection patterns
 * @param {string} input - The input string to analyze
 * @param {Object} options - Detection options
 * @returns {Object} Detection result with severity and details
 */
function detectSQLInjection (input, options = {}) {
  if (typeof input !== 'string') {
    return { detected: false, severity: null, patterns: [] };
  }

  const detectedPatterns = [];
  let maxSeverity = null;

  // Check SQL keywords
  const keywordResult = checkSQLKeywords(input);
  if (keywordResult.detected) {
    detectedPatterns.push(...keywordResult.patterns);
    maxSeverity = getHigherSeverity(maxSeverity, keywordResult.severity);
  }

  // Check injection patterns
  const injectionResult = checkInjectionPatterns(input);
  if (injectionResult.detected) {
    detectedPatterns.push(...injectionResult.patterns);
    maxSeverity = getHigherSeverity(maxSeverity, injectionResult.severity);
  }

  // Check comment patterns
  const commentResult = checkCommentPatterns(input);
  if (commentResult.detected) {
    detectedPatterns.push(...commentResult.patterns);
    maxSeverity = getHigherSeverity(maxSeverity, commentResult.severity);
  }

  // Check database-specific patterns
  const dbSpecificResult = checkDatabaseSpecificPatterns(input);
  if (dbSpecificResult.detected) {
    detectedPatterns.push(...dbSpecificResult.patterns);
    maxSeverity = getHigherSeverity(maxSeverity, dbSpecificResult.severity);
  }

  // Check encoded patterns
  const encodedResult = checkEncodedPatterns(input);
  if (encodedResult.detected) {
    detectedPatterns.push(...encodedResult.patterns);
    maxSeverity = getHigherSeverity(maxSeverity, encodedResult.severity);
  }

  // Check bypass patterns
  const bypassResult = checkBypassPatterns(input);
  if (bypassResult.detected) {
    detectedPatterns.push(...bypassResult.patterns);
    maxSeverity = getHigherSeverity(maxSeverity, bypassResult.severity);
  }

  return {
    detected: detectedPatterns.length > 0,
    severity: maxSeverity,
    patterns: detectedPatterns,
    message: detectedPatterns.length > 0
      ? `SQL injection patterns detected: ${detectedPatterns.join(', ')}`
      : null
  };
}

/**
 * Check for dangerous SQL keywords
 */
function checkSQLKeywords (input) {
  const detected = [];

  for (const pattern of SQL_KEYWORDS) {
    if (pattern.test(input)) {
      detected.push(`sql_keyword:${pattern.source}`);
    }
  }

  return {
    detected: detected.length > 0,
    severity: detected.length > 0 ? SEVERITY_LEVELS.HIGH : null,
    patterns: detected
  };
}

/**
 * Check for SQL injection attack patterns
 */
function checkInjectionPatterns (input) {
  const detected = [];

  for (const pattern of INJECTION_PATTERNS) {
    if (pattern.test(input)) {
      detected.push(`injection_pattern:${pattern.source}`);
    }
  }

  return {
    detected: detected.length > 0,
    severity: detected.length > 0 ? SEVERITY_LEVELS.CRITICAL : null,
    patterns: detected
  };
}

/**
 * Check for SQL comment patterns
 */
function checkCommentPatterns (input) {
  const detected = [];

  for (const pattern of COMMENT_PATTERNS) {
    if (pattern.test(input)) {
      detected.push(`comment_pattern:${pattern.source}`);
    }
  }

  return {
    detected: detected.length > 0,
    severity: detected.length > 0 ? SEVERITY_LEVELS.MEDIUM : null,
    patterns: detected
  };
}

/**
 * Check for database-specific patterns
 */
function checkDatabaseSpecificPatterns (input) {
  const detected = [];

  for (const [db, patterns] of Object.entries(DATABASE_SPECIFIC_PATTERNS)) {
    for (const pattern of patterns) {
      if (pattern.test(input)) {
        detected.push(`${db}_specific:${pattern.source}`);
      }
    }
  }

  return {
    detected: detected.length > 0,
    severity: detected.length > 0 ? SEVERITY_LEVELS.HIGH : null,
    patterns: detected
  };
}

/**
 * Check for encoded SQL patterns
 */
function checkEncodedPatterns (input) {
  const detected = [];

  for (const pattern of ENCODED_PATTERNS) {
    if (pattern.test(input)) {
      detected.push(`encoded_pattern:${pattern.source}`);
    }
  }

  return {
    detected: detected.length > 0,
    severity: detected.length > 0 ? SEVERITY_LEVELS.MEDIUM : null,
    patterns: detected
  };
}

/**
 * Check for bypass attempt patterns
 */
function checkBypassPatterns (input) {
  const detected = [];

  for (const pattern of BYPASS_PATTERNS) {
    if (pattern.test(input)) {
      detected.push(`bypass_pattern:${pattern.source}`);
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
 * Simple boolean check for SQL injection
 * @param {string} input - The input string to check
 * @returns {boolean} True if SQL injection patterns are detected
 */
function isSQLInjection (input) {
  return detectSQLInjection(input).detected;
}

module.exports = {
  // Main detection functions
  detectSQLInjection,
  isSQLInjection,

  // Individual checkers
  checkSQLKeywords,
  checkInjectionPatterns,
  checkCommentPatterns,
  checkDatabaseSpecificPatterns,
  checkEncodedPatterns,
  checkBypassPatterns,

  // Pattern exports for reuse
  SQL_KEYWORDS,
  INJECTION_PATTERNS,
  COMMENT_PATTERNS,
  DATABASE_SPECIFIC_PATTERNS,
  ENCODED_PATTERNS,
  BYPASS_PATTERNS,

  // Constants
  SEVERITY_LEVELS
};
