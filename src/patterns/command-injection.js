/**
 * Command Injection Pattern Detection Module
 *
 * Detects patterns commonly used in command injection attacks, including
 * shell metacharacters, dangerous commands, and command chaining attempts.
 *
 * Based on security best practices from DOMPurify, OWASP guidelines,
 * and common command injection vectors.
 */

const SEVERITY_LEVELS = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low'
};

/**
 * Shell metacharacters that can be used for command injection
 */
const SHELL_METACHARACTERS = [
  /[;&|`$(){}[\]]/, // Basic shell metacharacters
  /\|\s*\w+|&&|\|\||;|`/, // Command chaining patterns
  /\$\(.*?\)|\$\{.*?\}/, // Command substitution
  />\s*\/dev\/|<\s*\/dev\//, // Device redirection
  /<<\s*EOF|<<\s*\w+/, // Here documents
  /\*|\?|~|\^/ // Wildcards and expansion
];

/**
 * Dangerous system commands that should be blocked
 */
const DANGEROUS_COMMANDS = [
  // File system manipulation
  /\b(rm|del|format|mkfs|dd|shred)\s+/i,
  /\b(chmod|chown|chgrp)\s+/i,
  /\b(mount|umount|fdisk)\s+/i,

  // Network tools
  /\b(nc|netcat|telnet|ssh|scp|ftp)\s+/i,
  /\b(wget|curl|lynx)\s+/i,
  /\b(nmap|ping|traceroute)\s+/i,

  // System information
  /\b(ps|kill|killall|pkill)\s+/i,
  /\b(sudo|su|passwd)\s+/i,
  /\b(crontab|at|batch)\s+/i,

  // Code execution
  /\b(eval|exec|system|shell_exec)\s*\(/i,
  /\b(python|perl|ruby|node|bash|sh|zsh)\s+/i,

  // Data exfiltration
  /\b(mail|sendmail|base64|xxd|hexdump)\s+/i
];

/**
 * Command injection patterns specific to different shells
 */
const SHELL_SPECIFIC_PATTERNS = {
  bash: [
    /\$\(IFS=.*?\)/, // IFS manipulation
    /\$\{IFS\}/, // IFS variable usage
    /\|\s*tee\s+/, // Output redirection
    /\|\s*xargs\s+/ // Command execution via xargs
  ],
  powershell: [
    /Invoke-Expression|iex\s+/i, // PowerShell code execution
    /Start-Process|saps\s+/i, // Process execution
    /Get-Content|gc\s+/i, // File reading
    /Set-Content|sc\s+/i // File writing
  ],
  cmd: [
    /&\s*echo\s+/i, // Windows command chaining
    /\|\s*findstr\s+/i, // Windows text processing
    />\s*con\s*/i, // Console redirection
    /for\s+\/[lrf]\s+/i // Windows for loops
  ]
};

/**
 * Patterns for encoded command injection attempts
 */
const ENCODED_PATTERNS = [
  /\\x[0-9a-f]{2}/i, // Hex encoding
  /\\[0-7]{3}/, // Octal encoding
  /\\u[0-9a-f]{4}/i, // Unicode encoding
  /%[0-9a-f]{2}/i, // URL encoding
  /\+/ // URL encoding spaces
];

/**
 * Time-based command injection patterns
 */
const TIME_BASED_PATTERNS = [
  /sleep\s+\d+/i,
  /ping\s+-[nc]\s+\d+/i,
  /timeout\s+\d+/i,
  /usleep\s+\d+/i
];

/**
 * Main detection function for command injection patterns
 * @param {string} input - The input string to analyze
 * @param {Object} options - Detection options
 * @returns {Object} Detection result with severity and details
 */
function detectCommandInjection (input, options = {}) {
  if (typeof input !== 'string') {
    return { detected: false, severity: null, patterns: [] };
  }

  const detectedPatterns = [];
  let maxSeverity = null;

  // Check shell metacharacters
  const shellMetaResult = checkShellMetacharacters(input);
  if (shellMetaResult.detected) {
    detectedPatterns.push(...shellMetaResult.patterns);
    maxSeverity = getHigherSeverity(maxSeverity, shellMetaResult.severity);
  }

  // Check dangerous commands
  const dangerousCommandResult = checkDangerousCommands(input);
  if (dangerousCommandResult.detected) {
    detectedPatterns.push(...dangerousCommandResult.patterns);
    maxSeverity = getHigherSeverity(maxSeverity, dangerousCommandResult.severity);
  }

  // Check shell-specific patterns
  const shellSpecificResult = checkShellSpecificPatterns(input);
  if (shellSpecificResult.detected) {
    detectedPatterns.push(...shellSpecificResult.patterns);
    maxSeverity = getHigherSeverity(maxSeverity, shellSpecificResult.severity);
  }

  // Check encoded patterns
  const encodedResult = checkEncodedPatterns(input);
  if (encodedResult.detected) {
    detectedPatterns.push(...encodedResult.patterns);
    maxSeverity = getHigherSeverity(maxSeverity, encodedResult.severity);
  }

  // Check time-based patterns
  const timeBasedResult = checkTimeBasedPatterns(input);
  if (timeBasedResult.detected) {
    detectedPatterns.push(...timeBasedResult.patterns);
    maxSeverity = getHigherSeverity(maxSeverity, timeBasedResult.severity);
  }

  return {
    detected: detectedPatterns.length > 0,
    severity: maxSeverity,
    patterns: detectedPatterns,
    message: detectedPatterns.length > 0
      ? `Command injection patterns detected: ${detectedPatterns.join(', ')}`
      : null
  };
}

/**
 * Check for shell metacharacters
 */
function checkShellMetacharacters (input) {
  const detected = [];

  for (const pattern of SHELL_METACHARACTERS) {
    if (pattern.test(input)) {
      detected.push(`shell_metacharacter:${pattern.source}`);
    }
  }

  return {
    detected: detected.length > 0,
    severity: detected.length > 0 ? SEVERITY_LEVELS.HIGH : null,
    patterns: detected
  };
}

/**
 * Check for dangerous system commands
 */
function checkDangerousCommands (input) {
  const detected = [];

  for (const pattern of DANGEROUS_COMMANDS) {
    if (pattern.test(input)) {
      detected.push(`dangerous_command:${pattern.source}`);
    }
  }

  return {
    detected: detected.length > 0,
    severity: detected.length > 0 ? SEVERITY_LEVELS.CRITICAL : null,
    patterns: detected
  };
}

/**
 * Check for shell-specific injection patterns
 */
function checkShellSpecificPatterns (input) {
  const detected = [];

  for (const [shell, patterns] of Object.entries(SHELL_SPECIFIC_PATTERNS)) {
    for (const pattern of patterns) {
      if (pattern.test(input)) {
        detected.push(`${shell}_specific:${pattern.source}`);
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
 * Check for encoded command injection attempts
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
 * Check for time-based command injection patterns
 */
function checkTimeBasedPatterns (input) {
  const detected = [];

  for (const pattern of TIME_BASED_PATTERNS) {
    if (pattern.test(input)) {
      detected.push(`time_based:${pattern.source}`);
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
 * Simple boolean check for command injection
 * @param {string} input - The input string to check
 * @returns {boolean} True if command injection patterns are detected
 */
function isCommandInjection (input) {
  return detectCommandInjection(input).detected;
}

module.exports = {
  // Main detection functions
  detectCommandInjection,
  isCommandInjection,

  // Individual checkers
  checkShellMetacharacters,
  checkDangerousCommands,
  checkShellSpecificPatterns,
  checkEncodedPatterns,
  checkTimeBasedPatterns,

  // Pattern exports for reuse
  SHELL_METACHARACTERS,
  DANGEROUS_COMMANDS,
  SHELL_SPECIFIC_PATTERNS,
  ENCODED_PATTERNS,
  TIME_BASED_PATTERNS,

  // Constants
  SEVERITY_LEVELS
};
