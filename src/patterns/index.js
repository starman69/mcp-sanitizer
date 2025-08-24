/**
 * MCP Sanitizer Pattern Detection Modules
 *
 * Exports all pattern detection modules for the MCP Sanitizer.
 * This provides a centralized access point for all security pattern
 * detection functionality.
 *
 * Each module includes:
 * - Detection functions that return detailed results
 * - Simple boolean check functions
 * - Individual pattern checkers for granular control
 * - Exportable regex patterns for reuse
 * - Severity level constants
 *
 * Based on security best practices from HTML/XML sanitizers like DOMPurify,
 * OWASP guidelines, and comprehensive security research.
 */

const commandInjection = require('./command-injection');
const sqlInjection = require('./sql-injection');
const prototypePollution = require('./prototype-pollution');
const templateInjection = require('./template-injection');
const nosqlInjection = require('./nosql-injection');

/**
 * Combined severity levels from all modules
 */
const SEVERITY_LEVELS = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low'
};

/**
 * Pattern type constants for easier identification
 */
const PATTERN_TYPES = {
  COMMAND_INJECTION: 'command_injection',
  SQL_INJECTION: 'sql_injection',
  PROTOTYPE_POLLUTION: 'prototype_pollution',
  TEMPLATE_INJECTION: 'template_injection',
  NOSQL_INJECTION: 'nosql_injection'
};

/**
 * Comprehensive security pattern detection
 * Runs all pattern detection modules and combines results
 *
 * @param {string|Object} input - The input to analyze
 * @param {Object} options - Detection options
 * @returns {Object} Combined detection result
 */
function detectAllPatterns (input, options = {}) {
  const results = {
    detected: false,
    severity: null,
    patterns: [],
    detectionResults: {},
    summary: {
      totalPatterns: 0,
      patternsByType: {},
      patternsBySeverity: {}
    }
  };

  // Run all detection modules
  const detectionModules = [
    { name: PATTERN_TYPES.COMMAND_INJECTION, module: commandInjection },
    { name: PATTERN_TYPES.SQL_INJECTION, module: sqlInjection },
    { name: PATTERN_TYPES.PROTOTYPE_POLLUTION, module: prototypePollution },
    { name: PATTERN_TYPES.TEMPLATE_INJECTION, module: templateInjection },
    { name: PATTERN_TYPES.NOSQL_INJECTION, module: nosqlInjection }
  ];

  for (const { name, module } of detectionModules) {
    let detectResult;

    // Call the appropriate detection function based on module
    if (name === PATTERN_TYPES.COMMAND_INJECTION) {
      detectResult = module.detectCommandInjection(input, options);
    } else if (name === PATTERN_TYPES.SQL_INJECTION) {
      detectResult = module.detectSQLInjection(input, options);
    } else if (name === PATTERN_TYPES.PROTOTYPE_POLLUTION) {
      detectResult = module.detectPrototypePollution(input, options);
    } else if (name === PATTERN_TYPES.TEMPLATE_INJECTION) {
      detectResult = module.detectTemplateInjection(input, options);
    } else if (name === PATTERN_TYPES.NOSQL_INJECTION) {
      detectResult = module.detectNoSQLInjection(input, options);
    }

    // Store individual results
    results.detectionResults[name] = detectResult;

    // Combine patterns
    if (detectResult.detected) {
      results.detected = true;
      results.patterns.push(...detectResult.patterns.map(p => `${name}:${p}`));

      // Update severity to highest found
      results.severity = getHigherSeverity(results.severity, detectResult.severity);

      // Update summary
      results.summary.patternsByType[name] = detectResult.patterns.length;

      if (detectResult.severity) {
        results.summary.patternsBySeverity[detectResult.severity] =
          (results.summary.patternsBySeverity[detectResult.severity] || 0) + detectResult.patterns.length;
      }
    } else {
      results.summary.patternsByType[name] = 0;
    }
  }

  results.summary.totalPatterns = results.patterns.length;

  // Generate combined message
  if (results.detected) {
    const typeCount = Object.values(results.summary.patternsByType)
      .filter(count => count > 0).length;
    results.message = `${results.summary.totalPatterns} security patterns detected across ${typeCount} categories (severity: ${results.severity})`;
  }

  return results;
}

/**
 * Quick boolean check for any security patterns
 * @param {string|Object} input - The input to check
 * @returns {boolean} True if any security patterns are detected
 */
function hasSecurityPatterns (input) {
  return detectAllPatterns(input).detected;
}

/**
 * Get detailed security analysis with recommendations
 * @param {string|Object} input - The input to analyze
 * @param {Object} options - Analysis options
 * @returns {Object} Detailed security analysis
 */
function analyzeSecurityPatterns (input, options = {}) {
  const detection = detectAllPatterns(input, options);

  const analysis = {
    ...detection,
    recommendations: [],
    riskLevel: getRiskLevel(detection.severity),
    shouldBlock: detection.severity === SEVERITY_LEVELS.CRITICAL
  };

  // Generate recommendations based on detected patterns
  if (detection.detectionResults[PATTERN_TYPES.COMMAND_INJECTION]?.detected) {
    analysis.recommendations.push('Input contains command injection patterns. Sanitize shell metacharacters and validate against allowed commands.');
  }

  if (detection.detectionResults[PATTERN_TYPES.SQL_INJECTION]?.detected) {
    analysis.recommendations.push('Input contains SQL injection patterns. Use parameterized queries and validate SQL keywords.');
  }

  if (detection.detectionResults[PATTERN_TYPES.PROTOTYPE_POLLUTION]?.detected) {
    analysis.recommendations.push('Input contains prototype pollution patterns. Validate object keys and use Object.create(null) for safe objects.');
  }

  if (detection.detectionResults[PATTERN_TYPES.TEMPLATE_INJECTION]?.detected) {
    analysis.recommendations.push('Input contains template injection patterns. Sanitize template syntax and use safe template engines.');
  }

  if (detection.detectionResults[PATTERN_TYPES.NOSQL_INJECTION]?.detected) {
    analysis.recommendations.push('Input contains NoSQL injection patterns. Validate database operators, sanitize user input, and use parameterized queries.');
  }

  return analysis;
}

/**
 * Get risk level based on severity
 */
function getRiskLevel (severity) {
  switch (severity) {
    case SEVERITY_LEVELS.CRITICAL:
      return 'CRITICAL';
    case SEVERITY_LEVELS.HIGH:
      return 'HIGH';
    case SEVERITY_LEVELS.MEDIUM:
      return 'MEDIUM';
    case SEVERITY_LEVELS.LOW:
      return 'LOW';
    default:
      return 'NONE';
  }
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
 * Create a pattern detector configured for specific use cases
 * @param {Object} config - Configuration options
 * @returns {Object} Configured detector functions
 */
function createPatternDetector (config = {}) {
  const {
    enableCommandInjection = true,
    enableSQLInjection = true,
    enablePrototypePollution = true,
    enableTemplateInjection = true,
    enableNoSQLInjection = true,
    strictMode = false,
    customPatterns = []
  } = config;

  return {
    detect: (input, options = {}) => {
      const mergedOptions = { ...options, strictMode, customPatterns };

      if (!enableCommandInjection &&
          !enableSQLInjection &&
          !enablePrototypePollution &&
          !enableTemplateInjection &&
          !enableNoSQLInjection) {
        return { detected: false, severity: null, patterns: [] };
      }

      // Run only enabled detectors
      const results = {
        detected: false,
        severity: null,
        patterns: [],
        detectionResults: {}
      };

      if (enableCommandInjection) {
        const result = commandInjection.detectCommandInjection(input, mergedOptions);
        if (result.detected) {
          results.detected = true;
          results.patterns.push(...result.patterns);
          results.severity = getHigherSeverity(results.severity, result.severity);
        }
        results.detectionResults.commandInjection = result;
      }

      if (enableSQLInjection) {
        const result = sqlInjection.detectSQLInjection(input, mergedOptions);
        if (result.detected) {
          results.detected = true;
          results.patterns.push(...result.patterns);
          results.severity = getHigherSeverity(results.severity, result.severity);
        }
        results.detectionResults.sqlInjection = result;
      }

      if (enablePrototypePollution) {
        const result = prototypePollution.detectPrototypePollution(input, mergedOptions);
        if (result.detected) {
          results.detected = true;
          results.patterns.push(...result.patterns);
          results.severity = getHigherSeverity(results.severity, result.severity);
        }
        results.detectionResults.prototypePollution = result;
      }

      if (enableTemplateInjection) {
        const result = templateInjection.detectTemplateInjection(input, mergedOptions);
        if (result.detected) {
          results.detected = true;
          results.patterns.push(...result.patterns);
          results.severity = getHigherSeverity(results.severity, result.severity);
        }
        results.detectionResults.templateInjection = result;
      }

      if (enableNoSQLInjection) {
        const result = nosqlInjection.detectNoSQLInjection(input, mergedOptions);
        if (result.detected) {
          results.detected = true;
          results.patterns.push(...result.patterns);
          results.severity = getHigherSeverity(results.severity, result.severity);
        }
        results.detectionResults.nosqlInjection = result;
      }

      return results;
    },

    isSecure: (input, options = {}) => {
      return !this.detect(input, options).detected;
    }
  };
}

// Export individual modules
module.exports = {
  // Individual detection modules
  commandInjection,
  sqlInjection,
  prototypePollution,
  templateInjection,
  nosqlInjection,

  // Combined detection functions
  detectAllPatterns,
  hasSecurityPatterns,
  analyzeSecurityPatterns,
  createPatternDetector,

  // Utility functions
  getHigherSeverity,
  getRiskLevel,

  // Constants
  SEVERITY_LEVELS,
  PATTERN_TYPES
};
