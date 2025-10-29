/**
 * Default Configuration for MCP Sanitizer
 *
 * This module provides the default configuration settings for the MCP Sanitizer.
 * These settings represent secure defaults that can be overridden by users while
 * maintaining a secure baseline.
 *
 * Based on security best practices from OWASP guidelines, DOMPurify approach,
 * and comprehensive security research.
 */

/**
 * Default configuration options for MCP Sanitizer
 * @type {Object}
 */
const DEFAULT_CONFIG = {
  // Network Security Settings
  allowedProtocols: [
    'http', // Standard HTTP protocol
    'https', // Secure HTTP protocol
    'mcp' // MCP protocol for Model Context Protocol
  ],

  // Content Length and Depth Limits
  maxStringLength: 10000, // Maximum length for string values (10KB)
  maxDepth: 10, // Maximum object nesting depth
  maxArrayLength: 1000, // Maximum array length
  maxObjectKeys: 100, // Maximum number of object keys

  // File System Security
  allowedFileExtensions: [
    '.txt', // Plain text files
    '.json', // JSON data files
    '.md', // Markdown documentation
    '.csv', // Comma-separated values
    '.yaml', // YAML configuration files
    '.yml', // YAML configuration files (alternate extension)
    '.log' // Log files
  ],

  // Blocked Content Patterns
  blockedPatterns: [
    // Template injection patterns (Server-Side Template Injection)
    /\$\{.*?\}|\{\{.*?\}\}|<%.*?%>/,

    // Prototype pollution patterns
    /__proto__|constructor\.prototype|prototype\.constructor/i,

    // Code execution patterns
    /require\s*\(|import\s*\(|eval\s*\(|Function\s*\(/i,

    // Script injection patterns (XSS) - Heuristic detection
    // Detects HTML comments
    /<!--[\s\S]*?-->/i,
    // Detects well-formed script tags
    /<script[\s\S]*?<\/script>/i,
    // Detects unclosed or malformed script tags
    /<script[^>]*>/i,
    // Detects event handlers (improved to catch <img onload=alert(1)>)
    /<[^>]*[\s/]on\w+\s*=/i,
    // Detects javascript: protocol
    /javascript:/i,

    // Command chaining patterns
    /\|\s*\w+|&&|\|\||;|`/,

    // Path traversal patterns
    /\.\.\//,

    // SQL comment patterns
    /--[\s\S]*$|\/\*[\s\S]*?\*\//
  ],

  // SQL Injection Protection
  sqlKeywords: [
    // Data Definition Language (DDL)
    'DROP', 'CREATE', 'ALTER', 'TRUNCATE',

    // Data Manipulation Language (DML)
    'DELETE', 'INSERT', 'UPDATE',

    // Query operations
    'UNION', 'SELECT', 'FROM', 'WHERE',

    // Administrative functions
    'EXEC', 'EXECUTE', 'xp_', 'sp_',

    // Common injection patterns
    'OR 1=1', 'OR 1 = 1', 'AND 1=1', 'AND 1 = 1',

    // Comment patterns
    '--', '/*', '*/',

    // Information schema access
    'INFORMATION_SCHEMA', 'SYSOBJECTS', 'SYSCOLUMNS'
  ],

  // Command Injection Protection
  blockedCommands: [
    // File system operations
    'rm', 'del', 'delete', 'format', 'mkfs',

    // Network operations
    'nc', 'netcat', 'curl', 'wget', 'ping',

    // System information
    'ps', 'top', 'whoami', 'id', 'uname',

    // Process control
    'kill', 'killall', 'pkill',

    // Archive operations
    'tar', 'zip', 'unzip', 'gzip'
  ],

  // Shell Metacharacters (for command injection detection)
  shellMetacharacters: [
    ';', '&', '|', '`', '$', '(', ')', '{', '}',
    '[', ']', '<', '>', '"', "'", '\\', '\n', '\r'
  ],

  // Security Policy Settings
  strictMode: false, // Enable strict validation mode
  logSecurityEvents: true, // Log security violations
  blockOnSeverity: 'critical', // Block requests at this severity level or higher

  // Pattern Detection Configuration
  patternDetection: {
    enableCommandInjection: true,
    enableSQLInjection: true,
    enablePrototypePollution: true,
    enableTemplateInjection: true,
    enableXSSDetection: true,
    enablePathTraversal: true
  },

  // Context-Specific Settings
  contextSettings: {
    // File path validation
    filePath: {
      allowAbsolutePaths: false,
      allowedDirectories: [],
      blockedDirectories: [
        '/etc', '/proc', '/sys', '/dev', '/root',
        'C:\\Windows', 'C:\\System32', 'C:\\Program Files'
      ]
    },

    // URL validation
    url: {
      allowPrivateIPs: false,
      allowLocalhostWithoutPort: false,
      maxURLLength: 2048,
      blockedDomains: [],
      allowedDomains: []
    },

    // Command validation
    command: {
      allowedCommands: [],
      blockedCommands: [],
      maxCommandLength: 1000
    }
  },

  // Output Configuration
  outputOptions: {
    includeWarnings: true,
    includeMetadata: false,
    sanitizeOutput: true,
    htmlEncode: true
  },

  // Performance Settings
  performance: {
    timeoutMs: 5000, // Maximum processing time per request
    maxConcurrentRequests: 100, // Maximum concurrent sanitization requests
    enableCaching: false // Enable result caching (disabled by default for security)
  },

  // Custom Pattern Support
  customPatterns: {
    enabled: false,
    patterns: []
  }
};

/**
 * Configuration schema for validation
 * Each key maps to a validation function
 */
const CONFIG_SCHEMA = {
  allowedProtocols: (value) => {
    if (!Array.isArray(value)) {
      throw new Error('allowedProtocols must be an array');
    }
    if (!value.every(protocol => typeof protocol === 'string')) {
      throw new Error('All protocols must be strings');
    }
  },

  maxStringLength: (value) => {
    if (typeof value !== 'number' || value < 0) {
      throw new Error('maxStringLength must be a non-negative number');
    }
  },

  maxDepth: (value) => {
    if (typeof value !== 'number' || value < 0) {
      throw new Error('maxDepth must be a non-negative number');
    }
  },

  maxArrayLength: (value) => {
    if (typeof value !== 'number' || value < 0) {
      throw new Error('maxArrayLength must be a non-negative number');
    }
  },

  maxObjectKeys: (value) => {
    if (typeof value !== 'number' || value < 0) {
      throw new Error('maxObjectKeys must be a non-negative number');
    }
  },

  allowedFileExtensions: (value) => {
    if (!Array.isArray(value)) {
      throw new Error('allowedFileExtensions must be an array');
    }
    if (!value.every(ext => typeof ext === 'string' && ext.startsWith('.'))) {
      throw new Error('All file extensions must be strings starting with a dot');
    }
  },

  blockedPatterns: (value) => {
    if (!Array.isArray(value)) {
      throw new Error('blockedPatterns must be an array');
    }
    if (!value.every(pattern => pattern instanceof RegExp)) {
      throw new Error('All blocked patterns must be RegExp objects');
    }
  },

  sqlKeywords: (value) => {
    if (!Array.isArray(value)) {
      throw new Error('sqlKeywords must be an array');
    }
    if (!value.every(keyword => typeof keyword === 'string')) {
      throw new Error('All SQL keywords must be strings');
    }
  },

  strictMode: (value) => {
    if (typeof value !== 'boolean') {
      throw new Error('strictMode must be a boolean');
    }
  },

  logSecurityEvents: (value) => {
    if (typeof value !== 'boolean') {
      throw new Error('logSecurityEvents must be a boolean');
    }
  },

  blockOnSeverity: (value) => {
    const validSeverities = ['low', 'medium', 'high', 'critical'];
    if (!validSeverities.includes(value)) {
      throw new Error(`blockOnSeverity must be one of: ${validSeverities.join(', ')}`);
    }
  }
};

/**
 * Deep merge function that handles RegExp objects
 * @param {Object} target - Target object (will be extended)
 * @param {Object} source - Source object (will override target)
 * @returns {Object} Merged configuration
 */
function deepMerge (target, source) {
  if (typeof target !== 'object' || target === null) {
    target = {};
  }
  if (typeof source !== 'object' || source === null) {
    return target;
  }

  const result = { ...target };

  for (const key in source) {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      if (typeof source[key] === 'object' &&
          source[key] !== null &&
          !Array.isArray(source[key]) &&
          !(source[key] instanceof RegExp)) {
        // Deep merge objects
        result[key] = deepMerge(target[key] || {}, source[key]);
      } else if (source[key] instanceof RegExp) {
        // Clone RegExp objects
        result[key] = new RegExp(source[key].source, source[key].flags);
      } else if (Array.isArray(source[key])) {
        // For arrays, completely replace with source array (cloning RegExp objects)
        result[key] = source[key].map(item =>
          item instanceof RegExp
            ? new RegExp(item.source, item.flags)
            : item
        );
      } else {
        // For primitive values, use source value
        result[key] = source[key];
      }
    }
  }

  return result;
}

/**
 * Merge user configuration with default configuration
 * @param {Object} target - Target configuration (defaults to DEFAULT_CONFIG)
 * @param {Object} source - Source configuration to merge in
 * @returns {Object} Merged configuration
 */
function mergeConfig (target = DEFAULT_CONFIG, source = {}) {
  // If called with one parameter, assume it's merging with DEFAULT_CONFIG
  if (arguments.length === 1 && typeof target === 'object') {
    source = target;
    target = DEFAULT_CONFIG;
  }

  return deepMerge(target, source);
}

/**
 * Validate configuration against schema
 * @param {Object} config - Configuration to validate
 * @throws {Error} If configuration is invalid
 */
function validateConfig (config) {
  for (const [key, validator] of Object.entries(CONFIG_SCHEMA)) {
    if (key in config) {
      try {
        validator(config[key]);
      } catch (error) {
        throw new Error(`Invalid configuration for '${key}': ${error.message}`);
      }
    }
  }
}

/**
 * Create a validated configuration object
 * @param {Object} userConfig - User-provided configuration
 * @returns {Object} Validated and merged configuration
 */
function createConfig (userConfig = {}) {
  const mergedConfig = mergeConfig(userConfig);
  validateConfig(mergedConfig);
  return mergedConfig;
}

/**
 * Get default configuration (read-only)
 * @returns {Object} Deep copy of default configuration
 */
function getDefaultConfig () {
  // Deep clone function that preserves RegExp objects
  function deepClone (obj) {
    if (obj === null || typeof obj !== 'object') {
      return obj;
    }

    if (obj instanceof RegExp) {
      return new RegExp(obj.source, obj.flags);
    }

    if (Array.isArray(obj)) {
      return obj.map(item => deepClone(item));
    }

    const cloned = {};
    for (const key in obj) {
      if (Object.prototype.hasOwnProperty.call(obj, key)) {
        cloned[key] = deepClone(obj[key]);
      }
    }

    return cloned;
  }

  return deepClone(DEFAULT_CONFIG);
}

module.exports = {
  DEFAULT_CONFIG,
  CONFIG_SCHEMA,
  deepMerge,
  mergeConfig,
  validateConfig,
  createConfig,
  getDefaultConfig
};
