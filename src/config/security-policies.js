/**
 * Security Policies for MCP Sanitizer
 *
 * This module provides predefined security policies that can be used to configure
 * the MCP Sanitizer for different security requirements. Similar to DOMPurify's
 * approach, this provides easy-to-use presets for common security scenarios.
 *
 * Security Policies Available:
 * - STRICT: Maximum security, blocks most potentially dangerous content
 * - MODERATE: Balanced security and functionality
 * - PERMISSIVE: Minimal restrictions, allows most content with basic validation
 * - DEVELOPMENT: Relaxed settings for development environments
 * - PRODUCTION: Secure settings optimized for production use
 */

// const { DEFAULT_CONFIG } = require('./default-config') // Unused - commented out to fix ESLint

/**
 * STRICT Security Policy
 * Maximum security with aggressive filtering and minimal allowed content.
 * Recommended for high-security environments and untrusted input processing.
 */
const STRICT_POLICY = {
  // Network restrictions
  allowedProtocols: ['https'], // Only secure HTTPS allowed

  // Aggressive length and depth limits
  maxStringLength: 1000, // Very short strings only
  maxDepth: 3, // Shallow object nesting
  maxArrayLength: 100, // Small arrays only
  maxObjectKeys: 20, // Limited object complexity

  // Minimal file type support
  allowedFileExtensions: ['.txt', '.json'],

  // These patterns provide fast heuristic detection as part of defense-in-depth.
  blockedPatterns: [
    // All template injection patterns
    /\$\{.*?\}|\{\{.*?\}\}|<%.*?%>|\[\[.*?\]\]/,

    // All prototype pollution patterns
    /__proto__|constructor\.prototype|prototype\.constructor|prototype\[|constructor\[/i,

    // All code execution patterns
    /require\s*\(|import\s*\(|eval\s*\(|Function\s*\(|setTimeout\s*\(|setInterval\s*\(/i,

    // XSS patterns (heuristic detection - see docs for limitations)
    /<!--[\s\S]*?-->/i, // HTML comments
    /<script[\s\S]*?<\/script>/i, // Well-formed script tags
    /<script[^>]*>/i, // Unclosed/malformed script tags
    /<[^>]*[\s/]on\w+\s*=/i, // Event handlers (improved pattern)
    /javascript:/i, // JavaScript protocol
    /data:/i, // Data protocol (can contain scripts)

    // All command patterns
    /\|\s*\w+|&&|\|\||;|`|\$\(|\$\{/,

    // Path traversal
    /\.\.\//,

    // Any SQL-like syntax
    /--[\s\S]*$|\/\*[\s\S]*?\*\/|'[^']*'|"[^"]*"/,

    // File system access patterns
    /file:\/\/|ftp:\/\/|\\\\/,

    // Network access patterns
    /http:\/\/localhost|http:\/\/127\.|http:\/\/10\.|http:\/\/192\.168\./i
  ],

  // Extensive SQL keyword blocking
  sqlKeywords: [
    'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER', 'TRUNCATE',
    'UNION', 'EXEC', 'EXECUTE', 'DECLARE', 'CAST', 'CONVERT', 'SUBSTRING',
    'ASCII', 'CHAR', 'NCHAR', 'VARCHAR', 'NVARCHAR', 'CONCAT', 'REPLACE',
    'xp_', 'sp_', 'sys', 'INFORMATION_SCHEMA', 'SYSOBJECTS', 'SYSCOLUMNS',
    'OR 1=1', 'OR 1 = 1', 'AND 1=1', 'AND 1 = 1', '--', '/*', '*/',
    'WAITFOR', 'DELAY', 'BENCHMARK', 'SLEEP', 'PG_SLEEP'
  ],

  // Strict command blocking
  blockedCommands: [
    'rm', 'del', 'delete', 'format', 'mkfs', 'dd', 'mv', 'cp', 'chmod', 'chown',
    'nc', 'netcat', 'curl', 'wget', 'ping', 'nslookup', 'dig', 'telnet', 'ssh',
    'ps', 'top', 'whoami', 'id', 'uname', 'hostname', 'ifconfig', 'ipconfig',
    'kill', 'killall', 'pkill', 'sudo', 'su', 'passwd', 'useradd', 'userdel',
    'tar', 'zip', 'unzip', 'gzip', 'gunzip', 'cat', 'head', 'tail', 'less', 'more'
  ],

  // Security settings
  strictMode: true,
  logSecurityEvents: true,
  blockOnSeverity: 'medium', // Block even medium severity issues

  // Pattern detection - all enabled
  patternDetection: {
    enableCommandInjection: true,
    enableSQLInjection: true,
    enablePrototypePollution: true,
    enableTemplateInjection: true,
    enableXSSDetection: true,
    enablePathTraversal: true
  },

  // Restrictive context settings
  contextSettings: {
    filePath: {
      allowAbsolutePaths: false,
      allowedDirectories: [],
      blockedDirectories: ['*'] // Block all directories
    },
    url: {
      allowPrivateIPs: false,
      allowLocalhostWithoutPort: false,
      maxURLLength: 512,
      blockedDomains: ['localhost', '127.0.0.1', '0.0.0.0'],
      allowedDomains: [] // Must explicitly allow domains
    },
    command: {
      allowedCommands: [], // No commands allowed
      maxCommandLength: 0
    }
  },

  // Conservative performance settings
  performance: {
    timeoutMs: 1000,
    maxConcurrentRequests: 10,
    enableCaching: false
  }
};

/**
 * MODERATE Security Policy
 * Balanced approach between security and functionality.
 * Suitable for most production applications with moderate security requirements.
 */
const MODERATE_POLICY = {
  // Standard protocols
  allowedProtocols: ['http', 'https', 'mcp'],

  // Reasonable limits
  maxStringLength: 5000,
  maxDepth: 8,
  maxArrayLength: 500,
  maxObjectKeys: 50,

  // Common file types
  allowedFileExtensions: ['.txt', '.json', '.md', '.csv', '.yaml', '.yml'],

  // Core security patterns
  blockedPatterns: [
    /\$\{.*?\}|\{\{.*?\}\}|<%.*?%>/,
    /__proto__|constructor\.prototype|prototype\.constructor/i,
    /require\s*\(|import\s*\(|eval\s*\(|Function\s*\(/i,
    // XSS patterns (heuristic detection)
    /<!--[\s\S]*?-->/i, // HTML comments
    /<script[\s\S]*?<\/script>/i, // Well-formed script tags
    /<script[^>]*>/i, // Unclosed/malformed script tags
    /<[^>]*[\s/]on\w+\s*=/i, // Event handlers (improved pattern)
    /javascript:/i, // JavaScript protocol
    /\|\s*\w+|&&|\|\||;|`/,
    /\.\.\//
  ],

  // Essential SQL keywords
  sqlKeywords: [
    'DROP', 'DELETE', 'INSERT', 'UPDATE', 'CREATE', 'ALTER', 'TRUNCATE',
    'UNION', 'EXEC', 'EXECUTE', 'xp_', 'sp_', 'INFORMATION_SCHEMA',
    'OR 1=1', 'OR 1 = 1', 'AND 1=1', 'AND 1 = 1', '--', '/*', '*/'
  ],

  // Common dangerous commands
  blockedCommands: [
    'rm', 'del', 'delete', 'format', 'mkfs', 'dd',
    'nc', 'netcat', 'curl', 'wget',
    'kill', 'killall', 'pkill', 'sudo', 'su'
  ],

  // Balanced security settings
  strictMode: false,
  logSecurityEvents: true,
  blockOnSeverity: 'high',

  // Most detection enabled
  patternDetection: {
    enableCommandInjection: true,
    enableSQLInjection: true,
    enablePrototypePollution: true,
    enableTemplateInjection: true,
    enableXSSDetection: true,
    enablePathTraversal: true
  },

  // Moderate context restrictions
  contextSettings: {
    filePath: {
      allowAbsolutePaths: false,
      allowedDirectories: ['./data', './uploads', './temp'],
      blockedDirectories: [
        '/etc', '/proc', '/sys', '/dev', '/root',
        'C:\\Windows', 'C:\\System32', 'C:\\Program Files'
      ]
    },
    url: {
      allowPrivateIPs: false,
      allowLocalhostWithoutPort: false,
      maxURLLength: 2048,
      blockedDomains: [],
      allowedDomains: []
    },
    command: {
      allowedCommands: ['ls', 'dir', 'pwd', 'whoami'],
      maxCommandLength: 500
    }
  },

  // Standard performance settings
  performance: {
    timeoutMs: 3000,
    maxConcurrentRequests: 50,
    enableCaching: false
  }
};

/**
 * PERMISSIVE Security Policy
 * Minimal restrictions with basic validation only.
 * Suitable for trusted environments and development scenarios.
 */
const PERMISSIVE_POLICY = {
  // All common protocols
  allowedProtocols: ['http', 'https', 'ftp', 'mcp', 'file'],

  // Generous limits
  maxStringLength: 50000,
  maxDepth: 20,
  maxArrayLength: 5000,
  maxObjectKeys: 500,

  // Many file types allowed
  allowedFileExtensions: [
    '.txt', '.json', '.md', '.csv', '.xml', '.yaml', '.yml',
    '.js', '.ts', '.html', '.css', '.log', '.conf', '.ini'
  ],

  // Minimal pattern blocking - only the most dangerous
  blockedPatterns: [
    /eval\s*\(/i, // Direct eval calls
    /<script[\s\S]*?<\/script>/i, // Well-formed script tags
    /<script[^>]*>/i, // Unclosed script tags
    /__proto__\s*:/ // Direct prototype pollution
  ],

  // Minimal SQL keyword blocking
  sqlKeywords: [
    'DROP DATABASE', 'DROP TABLE', 'DELETE FROM', 'TRUNCATE TABLE',
    'xp_cmdshell', 'sp_configure', '--', '/*'
  ],

  // Few blocked commands
  blockedCommands: [
    'rm -rf', 'del /s', 'format', 'mkfs',
    'sudo rm', 'sudo del'
  ],

  // Relaxed security settings
  strictMode: false,
  logSecurityEvents: false,
  blockOnSeverity: 'critical',

  // Selective detection
  patternDetection: {
    enableCommandInjection: true,
    enableSQLInjection: true,
    enablePrototypePollution: true,
    enableTemplateInjection: false, // Disabled for flexibility
    enableXSSDetection: true,
    enablePathTraversal: false // Disabled for flexibility
  },

  // Permissive context settings
  contextSettings: {
    filePath: {
      allowAbsolutePaths: true,
      allowedDirectories: ['*'],
      blockedDirectories: ['/etc/passwd', '/etc/shadow']
    },
    url: {
      allowPrivateIPs: true,
      allowLocalhostWithoutPort: true,
      maxURLLength: 8192,
      blockedDomains: [],
      allowedDomains: []
    },
    command: {
      allowedCommands: ['*'],
      maxCommandLength: 2000
    }
  },

  // High performance settings
  performance: {
    timeoutMs: 10000,
    maxConcurrentRequests: 200,
    enableCaching: true
  }
};

/**
 * DEVELOPMENT Security Policy
 * Optimized for development environments with debugging capabilities.
 * Includes relaxed restrictions but maintains core security.
 */
const DEVELOPMENT_POLICY = {
  ...MODERATE_POLICY,

  // Development-friendly protocols
  allowedProtocols: ['http', 'https', 'mcp', 'file'],

  // Higher limits for development data
  maxStringLength: 20000,
  maxDepth: 15,
  maxArrayLength: 2000,
  maxObjectKeys: 200,

  // Development file types
  allowedFileExtensions: [
    '.txt', '.json', '.md', '.csv', '.xml', '.yaml', '.yml',
    '.js', '.ts', '.html', '.css', '.log', '.conf', '.ini',
    '.env', '.example', '.template'
  ],

  // Less strict patterns for development flexibility
  blockedPatterns: [
    /__proto__|constructor\.prototype/i,
    /eval\s*\(/i,
    /<script[\s\S]*?<\/script>/i, // Well-formed script tags
    /<script[^>]*>/i, // Unclosed script tags
    /\|\s*rm|\|\s*del/
  ],

  // Development settings
  strictMode: false,
  logSecurityEvents: true,
  blockOnSeverity: 'high',

  // Allow localhost access
  contextSettings: {
    ...MODERATE_POLICY.contextSettings,
    url: {
      allowPrivateIPs: true,
      allowLocalhostWithoutPort: true,
      maxURLLength: 4096,
      blockedDomains: [],
      allowedDomains: []
    },
    command: {
      allowedCommands: ['ls', 'dir', 'pwd', 'whoami', 'echo', 'cat', 'head', 'tail'],
      maxCommandLength: 1000
    }
  },

  // Relaxed performance for debugging
  performance: {
    timeoutMs: 15000,
    maxConcurrentRequests: 100,
    enableCaching: false // Disabled for fresh results during development
  }
};

/**
 * PRODUCTION Security Policy
 * Optimized for production environments with security and performance balance.
 * Stricter than moderate but maintains necessary functionality.
 */
const PRODUCTION_POLICY = {
  ...MODERATE_POLICY,

  // Production-secure protocols only
  allowedProtocols: ['https', 'mcp'],

  // Production-appropriate limits
  maxStringLength: 8000,
  maxDepth: 10,
  maxArrayLength: 1000,
  maxObjectKeys: 100,

  // Production file types
  allowedFileExtensions: ['.txt', '.json', '.md', '.csv', '.yaml', '.yml', '.log'],

  // Enhanced security patterns
  blockedPatterns: [
    ...MODERATE_POLICY.blockedPatterns,
    /file:\/\/|ftp:\/\//i, // Block file and FTP protocols
    /data:\/\/[^,]*base64/i, // Block base64 data URLs
    /\beval\b|\bexec\b/i // Block eval and exec keywords
  ],

  // Production security settings
  strictMode: true,
  logSecurityEvents: true,
  blockOnSeverity: 'medium',

  // All detection enabled for production
  patternDetection: {
    enableCommandInjection: true,
    enableSQLInjection: true,
    enablePrototypePollution: true,
    enableTemplateInjection: true,
    enableXSSDetection: true,
    enablePathTraversal: true
  },

  // Secure context settings
  contextSettings: {
    filePath: {
      allowAbsolutePaths: false,
      allowedDirectories: ['./data', './uploads'],
      blockedDirectories: [
        '/etc', '/proc', '/sys', '/dev', '/root', '/var/log',
        'C:\\Windows', 'C:\\System32', 'C:\\Program Files'
      ]
    },
    url: {
      allowPrivateIPs: false,
      allowLocalhostWithoutPort: false,
      maxURLLength: 2048,
      blockedDomains: ['localhost', '127.0.0.1', '0.0.0.0'],
      allowedDomains: [] // Should be configured per application
    },
    command: {
      allowedCommands: [], // No commands in production by default
      maxCommandLength: 0
    }
  },

  // Production performance settings
  performance: {
    timeoutMs: 5000,
    maxConcurrentRequests: 100,
    enableCaching: true // Enable for production performance
  }
};

/**
 * Available security policies
 */
const SECURITY_POLICIES = {
  STRICT: STRICT_POLICY,
  MODERATE: MODERATE_POLICY,
  PERMISSIVE: PERMISSIVE_POLICY,
  DEVELOPMENT: DEVELOPMENT_POLICY,
  PRODUCTION: PRODUCTION_POLICY
};

/**
 * Policy names for validation
 */
const POLICY_NAMES = Object.keys(SECURITY_POLICIES);

/**
 * Get a security policy by name
 * @param {string} policyName - Name of the security policy
 * @returns {Object} Security policy configuration
 * @throws {Error} If policy name is invalid
 */
function getSecurityPolicy (policyName) {
  if (typeof policyName !== 'string') {
    throw new Error('Policy name must be a string');
  }

  const upperPolicyName = policyName.toUpperCase();

  if (!SECURITY_POLICIES[upperPolicyName]) {
    throw new Error(`Invalid security policy: ${policyName}. Available policies: ${POLICY_NAMES.join(', ')}`);
  }

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

  return deepClone(SECURITY_POLICIES[upperPolicyName]);
}

/**
 * Create a custom policy by extending an existing policy
 * @param {string} basePolicyName - Base policy to extend
 * @param {Object} customizations - Custom settings to override
 * @returns {Object} Custom security policy
 */
function createCustomPolicy (basePolicyName, customizations = {}) {
  const basePolicy = getSecurityPolicy(basePolicyName);

  // Deep merge function that handles RegExp objects
  function deepMerge (target, source) {
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

  return deepMerge(basePolicy, customizations);
}

/**
 * Get policy recommendations based on environment
 * @param {string} environment - Environment type ('development', 'staging', 'production')
 * @param {string} trustLevel - Trust level ('high', 'medium', 'low')
 * @returns {Object} Policy recommendation
 */
function getPolicyRecommendation (environment = 'production', trustLevel = 'low') {
  const recommendations = {
    development: {
      high: 'PERMISSIVE',
      medium: 'DEVELOPMENT',
      low: 'MODERATE'
    },
    staging: {
      high: 'MODERATE',
      medium: 'MODERATE',
      low: 'PRODUCTION'
    },
    production: {
      high: 'MODERATE',
      medium: 'PRODUCTION',
      low: 'STRICT'
    }
  };

  const envRecommendations = recommendations[environment.toLowerCase()];
  if (!envRecommendations) {
    throw new Error(`Invalid environment: ${environment}. Use 'development', 'staging', or 'production'`);
  }

  const policyName = envRecommendations[trustLevel.toLowerCase()];
  if (!policyName) {
    throw new Error(`Invalid trust level: ${trustLevel}. Use 'high', 'medium', or 'low'`);
  }

  return {
    recommended: policyName,
    policy: getSecurityPolicy(policyName),
    rationale: `Recommended ${policyName} policy for ${environment} environment with ${trustLevel} trust level`
  };
}

/**
 * Validate that a policy meets minimum security requirements
 * @param {Object} policy - Policy to validate
 * @param {Object} requirements - Minimum security requirements
 * @returns {Object} Validation result
 */
function validatePolicyRequirements (policy, requirements = {}) {
  const result = {
    valid: true,
    violations: [],
    warnings: []
  };

  // Check basic security requirements
  if (requirements.requireHTTPS && policy.allowedProtocols.includes('http')) {
    result.violations.push('Policy allows HTTP protocol when HTTPS is required');
    result.valid = false;
  }

  if (requirements.maxStringLength && policy.maxStringLength > requirements.maxStringLength) {
    result.violations.push(`Policy allows strings longer than required maximum: ${requirements.maxStringLength}`);
    result.valid = false;
  }

  if (requirements.blockSeverity) {
    const severityOrder = ['low', 'medium', 'high', 'critical'];
    const requiredIndex = severityOrder.indexOf(requirements.blockSeverity);
    const policyIndex = severityOrder.indexOf(policy.blockOnSeverity);

    if (policyIndex > requiredIndex) {
      result.violations.push(`Policy blocks at ${policy.blockOnSeverity} severity when ${requirements.blockSeverity} or higher is required`);
      result.valid = false;
    }
  }

  // Check for security features
  if (requirements.requireAllPatternDetection) {
    const requiredDetections = Object.keys(policy.patternDetection);
    for (const detection of requiredDetections) {
      if (!policy.patternDetection[detection]) {
        result.warnings.push(`Pattern detection disabled for ${detection}`);
      }
    }
  }

  return result;
}

module.exports = {
  SECURITY_POLICIES,
  POLICY_NAMES,
  STRICT_POLICY,
  MODERATE_POLICY,
  PERMISSIVE_POLICY,
  DEVELOPMENT_POLICY,
  PRODUCTION_POLICY,
  getSecurityPolicy,
  createCustomPolicy,
  getPolicyRecommendation,
  validatePolicyRequirements
};
