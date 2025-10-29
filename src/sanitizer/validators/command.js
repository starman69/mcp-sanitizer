/**
 * Command Validator for MCP Sanitizer
 *
 * This module provides comprehensive validation and sanitization for command strings,
 * protecting against command injection attacks, dangerous commands, and shell metacharacters.
 *
 * Features:
 * - Command injection pattern detection
 * - Shell metacharacter validation
 * - Dangerous command blocking
 * - Command whitelist/blacklist support
 * - Argument validation and sanitization
 * - Cross-platform command handling
 * - Configurable validation rules
 * - Async validation support
 *
 * @example
 * const { CommandValidator } = require('./command');
 * const validator = new CommandValidator(config);
 *
 * const result = await validator.validate('ls -la /home');
 * if (result.isValid) {
 *   console.log('Sanitized command:', result.sanitized);
 * } else {
 *   console.error('Validation failed:', result.warnings);
 * }
 */

// const { validationUtils, stringUtils } = require('../../utils') // Unused - commented to fix ESLint
const { commandInjection, detectAllPatterns, SEVERITY_LEVELS } = require('../../patterns');
const shellQuote = require('shell-quote');
// const { securityDecode } = require('../../utils/security-decoder') // Unused
// CVE-TBD-001 FIX: Import unified parser for consistent string normalization
const { parseUnified } = require('../../utils/unified-parser');

/**
 * Command validation severity levels
 */
const SEVERITY = {
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical'
};

/**
 * Default configuration for command validation
 */
const DEFAULT_CONFIG = {
  allowedCommands: [], // Empty array means all commands allowed (use with caution)
  blockedCommands: [
    'rm', 'del', 'format', 'mkfs', 'dd', 'fdisk',
    'nc', 'netcat', 'telnet', 'ssh', 'ftp',
    'wget', 'curl', 'lynx', 'links',
    'eval', 'exec', 'system', 'popen',
    'sudo', 'su', 'passwd', 'chmod', 'chown',
    'mount', 'umount', 'kill', 'killall',
    'reboot', 'shutdown', 'halt', 'init'
  ],
  allowShellMetacharacters: false,
  allowRedirection: false,
  allowPipes: false,
  allowBackgroundExecution: false,
  allowSubcommands: false,
  maxCommandLength: 1000,
  maxArguments: 20,
  maxArgumentLength: 500,
  allowEnvironmentVariables: false,
  strictMode: false,
  customPatterns: [],
  platformSpecific: {
    windows: {
      blockedCommands: ['del', 'format', 'diskpart', 'reg', 'sc', 'net', 'runas'],
      dangerousExtensions: ['.exe', '.bat', '.cmd', '.ps1', '.vbs', '.scr']
    },
    unix: {
      blockedCommands: ['rm', 'dd', 'mkfs', 'fdisk', 'mount', 'umount', 'sudo', 'su'],
      dangerousPaths: ['/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/']
    }
  }
};

/**
 * Shell metacharacters that can be dangerous
 */
const SHELL_METACHARACTERS = {
  dangerous: ['&', '|', ';', '`', '$', '(', ')', '{', '}', '[', ']', '<', '>', '*', '?'],
  redirection: ['>', '<', '>>', '<<'],
  pipes: ['|', '||', '&&'],
  background: ['&'],
  substitution: ['`', '$()'],
  globbing: ['*', '?', '[', ']', '{', '}']
};

/**
 * Command injection patterns specific to this validator
 */
const INJECTION_PATTERNS = [
  /[;&|`$(){}[\]<>*?]/, // Shell metacharacters
  /\|\s*(nc|netcat|telnet|ssh)\s+/i, // Network command pipes
  />\s*\/dev\/|<\s*\/dev\//, // Device redirection
  /\$\([^)]{0,200}\)|`[^`]{0,200}`/, // Command substitution (bounded for safety)
  /&&|\|\||;/, // Command chaining
  />\s*&\s*\d+|<\s*&\s*\d+/, // File descriptor redirection
  /\\\w+/, // Escape sequences
  /\${[^}]{0,200}}/, // Variable expansion (bounded)
  /\s+-[^-\s]*e[^-\s]*\s+/, // Execute flags in various commands
  // Sensitive file access patterns
  /\/etc\/(passwd|shadow|sudoers|hosts)/i, // Unix sensitive files
  /\/proc\//i, // Process information
  /\/sys\//i, // System information
  /\/dev\//i, // Device files
  /C:\\Windows\\System32/i, // Windows system files
  /\.ssh\//i, // SSH keys
  /\.aws\//i, // AWS credentials
  /\.env/i // Environment files
];

/**
 * Command Validator Class
 */
class CommandValidator {
  /**
   * Create a new command validator
   * @param {Object} config - Validation configuration
   */
  constructor (config = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.platform = this._detectPlatform();
  }

  /**
   * Validate a command string
   * @param {string} command - The command to validate
   * @param {Object} options - Additional validation options
   * @returns {Promise<Object>} Validation result
   */
  async validate (command, options = {}) {
    const result = {
      isValid: false,
      sanitized: null,
      warnings: [],
      severity: null,
      metadata: {
        originalCommand: command,
        parsedCommand: null,
        commandName: null,
        arguments: [],
        containsMetacharacters: false,
        detectedPatterns: [],
        wasDecoded: false,
        decodingSteps: []
      }
    };

    try {
      // Basic input validation
      if (typeof command !== 'string') {
        result.warnings.push('Command must be a string');
        result.severity = SEVERITY.HIGH;
        return result;
      }

      if (!command || command.trim().length === 0) {
        result.warnings.push('Command cannot be empty');
        result.severity = SEVERITY.HIGH;
        return result;
      }

      // Check command length
      if (command.length > this.config.maxCommandLength) {
        result.warnings.push(`Command exceeds maximum length of ${this.config.maxCommandLength} characters`);
        result.severity = SEVERITY.MEDIUM;
        return result;
      }

      // CVE-TBD-001 FIX: Use unified parser for consistent normalization
      const normalizedStr = parseUnified(command, {
        type: 'command',
        strictMode: true
      });

      const trimmedCommand = normalizedStr.getNormalized().trim();
      const metadata = normalizedStr.getMetadata();

      // Update result metadata with parsing information
      if (metadata.wasDecoded) {
        result.metadata.wasDecoded = true;
        result.metadata.decodingSteps = metadata.decodingSteps;
        result.warnings.push(`Encoded/dangerous sequences detected and processed: ${metadata.decodingSteps.join(', ')}`);
        result.severity = SEVERITY.HIGH; // Encoding in commands is suspicious
      }

      // Check for security warnings from unified parser
      if (metadata.warnings && metadata.warnings.length > 0) {
        result.warnings.push(...metadata.warnings);
        result.severity = this._getHigherSeverity(result.severity, SEVERITY.HIGH);
      }

      // Check for newlines and null bytes before processing (should be removed by unified parser)
      if (trimmedCommand.includes('\n') || trimmedCommand.includes('\r') || trimmedCommand.includes('\0')) {
        result.warnings.push('Command contains dangerous control characters (newlines or null bytes)');
        result.severity = SEVERITY.CRITICAL;
        return result;
      }

      // Check for security patterns using command injection detector
      const injectionResult = commandInjection.detectCommandInjection(trimmedCommand);
      if (injectionResult.detected) {
        result.metadata.detectedPatterns = injectionResult.patterns;
        result.warnings.push(`Command injection patterns detected: ${injectionResult.patterns.join(', ')}`);
        result.severity = this._mapSeverity(injectionResult.severity);

        if (injectionResult.severity === SEVERITY_LEVELS.CRITICAL) {
          return result;
        }
      }

      // Run general pattern detection
      const patternResult = detectAllPatterns(trimmedCommand);
      if (patternResult.detected) {
        result.metadata.detectedPatterns.push(...patternResult.patterns);
        result.warnings.push(`Additional security patterns detected: ${patternResult.patterns.join(', ')}`);
        result.severity = this._getHigherSeverity(result.severity, this._mapSeverity(patternResult.severity));
      }

      // Parse command into components
      const parseResult = this._parseCommand(trimmedCommand);
      if (!parseResult.isValid) {
        result.warnings.push(...parseResult.warnings);
        result.severity = this._getHigherSeverity(result.severity, parseResult.severity);
        return result;
      }

      result.metadata.parsedCommand = parseResult.parsed;
      result.metadata.commandName = parseResult.parsed.command;
      result.metadata.arguments = parseResult.parsed.arguments;

      // Validate shell metacharacters
      const metacharResult = this._validateMetacharacters(trimmedCommand);
      if (!metacharResult.isValid) {
        result.warnings.push(...metacharResult.warnings);
        result.severity = this._getHigherSeverity(result.severity, metacharResult.severity);
        result.metadata.containsMetacharacters = true;

        if (metacharResult.severity === SEVERITY.CRITICAL) {
          return result;
        }
      }

      // Validate command name against whitelist/blacklist
      const commandResult = this._validateCommandName(parseResult.parsed.command);
      if (!commandResult.isValid) {
        result.warnings.push(...commandResult.warnings);
        result.severity = this._getHigherSeverity(result.severity, commandResult.severity);

        if (commandResult.severity === SEVERITY.CRITICAL) {
          return result;
        }
      }

      // Validate arguments
      const argsResult = this._validateArguments(parseResult.parsed.arguments);
      if (!argsResult.isValid) {
        result.warnings.push(...argsResult.warnings);
        result.severity = this._getHigherSeverity(result.severity, argsResult.severity);

        if (argsResult.severity === SEVERITY.CRITICAL) {
          return result;
        }
      }

      // Platform-specific validation
      const platformResult = this._validatePlatformSpecific(parseResult.parsed, trimmedCommand);
      if (!platformResult.isValid) {
        result.warnings.push(...platformResult.warnings);
        result.severity = this._getHigherSeverity(result.severity, platformResult.severity);

        if (platformResult.severity === SEVERITY.CRITICAL) {
          return result;
        }
      }

      // If we get here, the command is valid
      result.isValid = true;
      result.sanitized = trimmedCommand;

      // Set severity to lowest if there were warnings but command is still valid
      if (result.warnings.length === 0) {
        result.severity = null;
      } else if (!result.severity) {
        result.severity = SEVERITY.LOW;
      }
    } catch (error) {
      result.warnings.push(`Validation error: ${error.message}`);
      result.severity = SEVERITY.HIGH;
    }

    return result;
  }

  /**
   * Sanitize a command string
   * @param {string} command - The command to sanitize
   * @param {Object} options - Sanitization options
   * @returns {Promise<Object>} Sanitization result
   */
  async sanitize (command, options = {}) {
    const validationResult = await this.validate(command, options);

    if (validationResult.isValid) {
      return validationResult;
    }

    // Attempt to sanitize the command
    let sanitized = command;
    const warnings = [...validationResult.warnings];

    try {
      // Basic sanitization
      sanitized = sanitized.trim();

      // Remove or escape dangerous metacharacters
      if (!this.config.allowShellMetacharacters) {
        // Remove dangerous metacharacters
        sanitized = sanitized.replace(/[;&|`$(){}[\]<>*?]/g, '');
        warnings.push('Removed shell metacharacters');
      }

      // Remove command chaining
      sanitized = sanitized.split(/[;&|]{1,2}/)[0].trim();
      if (sanitized !== command.trim()) {
        warnings.push('Removed command chaining');
      }

      // Remove redirection
      sanitized = sanitized.replace(/\s*[<>]+\s*[^\s]*/g, '');
      if (sanitized !== command.trim()) {
        warnings.push('Removed redirection operators');
      }

      // Remove background execution
      sanitized = sanitized.replace(/\s*&\s*$/, '');

      // Limit argument count
      const parts = sanitized.split(/\s+/);
      if (parts.length > this.config.maxArguments + 1) { // +1 for command name
        sanitized = parts.slice(0, this.config.maxArguments + 1).join(' ');
        warnings.push(`Limited arguments to ${this.config.maxArguments}`);
      }

      // Limit argument lengths
      const sanitizedParts = sanitized.split(/\s+/).map(part => {
        if (part.length > this.config.maxArgumentLength) {
          warnings.push(`Truncated argument '${part}' to maximum length`);
          return part.substring(0, this.config.maxArgumentLength);
        }
        return part;
      });
      sanitized = sanitizedParts.join(' ');

      // If command becomes empty or too short after sanitization, reject it
      if (!sanitized || sanitized.length < 2) {
        return {
          isValid: false,
          sanitized: null,
          warnings: [...warnings, 'Command became too short or empty after sanitization'],
          severity: SEVERITY.HIGH,
          metadata: {
            ...validationResult.metadata,
            wasSanitized: false,
            sanitizationFailed: true
          }
        };
      }

      // Re-validate the sanitized command
      const revalidationResult = await this.validate(sanitized, options);

      return {
        isValid: revalidationResult.isValid,
        sanitized: revalidationResult.isValid ? revalidationResult.sanitized : null,
        warnings: [...warnings, ...revalidationResult.warnings],
        severity: this._getHigherSeverity(validationResult.severity, revalidationResult.severity),
        metadata: {
          ...validationResult.metadata,
          ...revalidationResult.metadata,
          wasSanitized: true,
          sanitizationApplied: true
        }
      };
    } catch (error) {
      return {
        isValid: false,
        sanitized: null,
        warnings: [...warnings, `Sanitization failed: ${error.message}`],
        severity: SEVERITY.HIGH,
        metadata: {
          ...validationResult.metadata,
          wasSanitized: false,
          sanitizationError: error.message
        }
      };
    }
  }

  /**
   * Parse a command string into components
   * @param {string} command - Command to parse
   * @returns {Object} Parse result
   * @private
   */
  _parseCommand (command) {
    const result = {
      isValid: true,
      warnings: [],
      severity: null,
      parsed: {
        command: null,
        arguments: [],
        fullCommand: command
      }
    };

    try {
      // Simple parsing - split by whitespace
      const parts = command.trim().split(/\s+/);

      if (parts.length === 0) {
        result.isValid = false;
        result.warnings.push('Unable to parse command');
        result.severity = SEVERITY.HIGH;
        return result;
      }

      result.parsed.command = parts[0];
      result.parsed.arguments = parts.slice(1);

      // Check for dangerous command patterns in the first part
      const commandPart = result.parsed.command.toLowerCase();

      // Check for path traversal in command name
      if (commandPart.includes('..') || commandPart.includes('/./') || commandPart.includes('\\.\\')) {
        result.warnings.push('Path traversal detected in command name');
        result.severity = SEVERITY.HIGH;
      }

      // Check for executable extensions (Windows)
      if (this.platform === 'windows') {
        const dangerousExts = this.config.platformSpecific.windows.dangerousExtensions;
        for (const ext of dangerousExts) {
          if (commandPart.endsWith(ext)) {
            result.warnings.push(`Potentially dangerous executable extension: ${ext}`);
            result.severity = this._getHigherSeverity(result.severity, SEVERITY.MEDIUM);
          }
        }
      }
    } catch (error) {
      result.isValid = false;
      result.warnings.push(`Command parsing failed: ${error.message}`);
      result.severity = SEVERITY.HIGH;
    }

    return result;
  }

  /**
   * Validate shell metacharacters
   * @param {string} command - Command to validate
   * @returns {Object} Validation result
   * @private
   */
  _validateMetacharacters (command) {
    const result = {
      isValid: true,
      warnings: [],
      severity: null
    };

    // Check for dangerous metacharacters
    for (const char of SHELL_METACHARACTERS.dangerous) {
      if (command.includes(char)) {
        const charType = this._getMetacharacterType(char);

        if (!this._isMetacharacterAllowed(char, charType)) {
          result.isValid = false;
          result.warnings.push(`Dangerous shell metacharacter detected: '${char}' (${charType})`);
          result.severity = this._getMetacharacterSeverity(char, charType);
        } else {
          result.warnings.push(`Warning: Shell metacharacter '${char}' detected but allowed`);
          result.severity = this._getHigherSeverity(result.severity, SEVERITY.LOW);
        }
      }
    }

    // Check for specific injection patterns
    for (const pattern of INJECTION_PATTERNS) {
      if (pattern.test(command)) {
        result.isValid = false;
        result.warnings.push(`Command injection pattern detected: ${pattern.source}`);
        result.severity = SEVERITY.CRITICAL;
      }
    }

    return result;
  }

  /**
   * Get the type of a metacharacter
   * @param {string} char - Metacharacter to classify
   * @returns {string} Character type
   * @private
   */
  _getMetacharacterType (char) {
    if (SHELL_METACHARACTERS.redirection.includes(char)) return 'redirection';
    if (SHELL_METACHARACTERS.pipes.includes(char)) return 'pipe';
    if (SHELL_METACHARACTERS.background.includes(char)) return 'background';
    if (SHELL_METACHARACTERS.substitution.includes(char)) return 'substitution';
    if (SHELL_METACHARACTERS.globbing.includes(char)) return 'globbing';
    return 'other';
  }

  /**
   * Check if a metacharacter is allowed based on configuration
   * @param {string} char - Metacharacter to check
   * @param {string} type - Character type
   * @returns {boolean} True if allowed
   * @private
   */
  _isMetacharacterAllowed (char, type) {
    if (this.config.allowShellMetacharacters) return true;

    switch (type) {
      case 'redirection':
        return this.config.allowRedirection;
      case 'pipe':
        return this.config.allowPipes;
      case 'background':
        return this.config.allowBackgroundExecution;
      case 'substitution':
        return this.config.allowSubcommands;
      default:
        return false;
    }
  }

  /**
   * Get severity level for metacharacter
   * @param {string} char - Metacharacter
   * @param {string} type - Character type
   * @returns {string} Severity level
   * @private
   */
  _getMetacharacterSeverity (char, type) {
    switch (type) {
      case 'substitution':
        return SEVERITY.CRITICAL;
      case 'pipe':
        return char === '|' ? SEVERITY.HIGH : SEVERITY.CRITICAL;
      case 'redirection':
        return SEVERITY.HIGH;
      case 'background':
        return SEVERITY.HIGH;
      default:
        return SEVERITY.MEDIUM;
    }
  }

  /**
   * Validate command name against whitelist/blacklist
   * @param {string} commandName - Command name to validate
   * @returns {Object} Validation result
   * @private
   */
  _validateCommandName (commandName) {
    const result = {
      isValid: true,
      warnings: [],
      severity: null
    };

    if (!commandName) {
      result.isValid = false;
      result.warnings.push('Command name is empty');
      result.severity = SEVERITY.HIGH;
      return result;
    }

    const lowerCommand = commandName.toLowerCase();

    // Check blacklist first (higher priority)
    if (this.config.blockedCommands.includes(lowerCommand)) {
      result.isValid = false;
      result.warnings.push(`Command '${commandName}' is blocked for security reasons`);
      result.severity = SEVERITY.CRITICAL;
      return result;
    }

    // Check whitelist if specified
    if (this.config.allowedCommands.length > 0) {
      if (!this.config.allowedCommands.includes(lowerCommand)) {
        result.isValid = false;
        result.warnings.push(`Command '${commandName}' is not in the allowed list`);
        result.severity = SEVERITY.HIGH;
      }
    }

    return result;
  }

  /**
   * Validate command arguments
   * @param {string[]} args - Arguments to validate
   * @returns {Object} Validation result
   * @private
   */
  _validateArguments (args) {
    const result = {
      isValid: true,
      warnings: [],
      severity: null
    };

    // Check argument count
    if (args.length > this.config.maxArguments) {
      result.warnings.push(`Too many arguments (${args.length} > ${this.config.maxArguments})`);
      result.severity = SEVERITY.MEDIUM;
    }

    // Validate each argument
    for (let i = 0; i < args.length; i++) {
      const arg = args[i];

      // Check argument length
      if (arg.length > this.config.maxArgumentLength) {
        result.warnings.push(`Argument ${i + 1} exceeds maximum length (${this.config.maxArgumentLength})`);
        result.severity = this._getHigherSeverity(result.severity, SEVERITY.MEDIUM);
      }

      // Check for dangerous patterns in arguments
      const patternResult = detectAllPatterns(arg);
      if (patternResult.detected) {
        result.warnings.push(`Security patterns detected in argument ${i + 1}: ${patternResult.patterns.join(', ')}`);
        result.severity = this._getHigherSeverity(result.severity, this._mapSeverity(patternResult.severity));
      }

      // Check for environment variables if not allowed
      if (!this.config.allowEnvironmentVariables && (arg.includes('$') || arg.includes('%'))) {
        result.warnings.push(`Environment variable detected in argument ${i + 1}`);
        result.severity = this._getHigherSeverity(result.severity, SEVERITY.MEDIUM);
      }
    }

    return result;
  }

  /**
   * Platform-specific validation
   * @param {Object} parsed - Parsed command object
   * @param {string} command - Original command string
   * @returns {Object} Validation result
   * @private
   */
  _validatePlatformSpecific (parsed, command) {
    const result = {
      isValid: true,
      warnings: [],
      severity: null
    };

    const platformConfig = this.config.platformSpecific[this.platform];
    if (!platformConfig) {
      return result; // No platform-specific rules
    }

    // Check platform-specific blocked commands
    if (platformConfig.blockedCommands) {
      const lowerCommand = parsed.command.toLowerCase();
      if (platformConfig.blockedCommands.includes(lowerCommand)) {
        result.isValid = false;
        result.warnings.push(`Command '${parsed.command}' is blocked on ${this.platform} platform`);
        result.severity = SEVERITY.CRITICAL;
      }
    }

    // Unix-specific checks
    if (this.platform === 'unix' && platformConfig.dangerousPaths) {
      for (const path of platformConfig.dangerousPaths) {
        if (command.includes(path)) {
          result.warnings.push(`Dangerous path detected: ${path}`);
          result.severity = this._getHigherSeverity(result.severity, SEVERITY.HIGH);
        }
      }
    }

    return result;
  }

  /**
   * Detect the current platform
   * @returns {string} Platform name
   * @private
   */
  _detectPlatform () {
    if (process.platform === 'win32') {
      return 'windows';
    }
    return 'unix'; // Covers Linux, macOS, etc.
  }

  /**
   * Map pattern detection severity to validator severity
   * @param {string} patternSeverity - Pattern detection severity
   * @returns {string} Validator severity
   * @private
   */
  _mapSeverity (patternSeverity) {
    const mapping = {
      [SEVERITY_LEVELS.LOW]: SEVERITY.LOW,
      [SEVERITY_LEVELS.MEDIUM]: SEVERITY.MEDIUM,
      [SEVERITY_LEVELS.HIGH]: SEVERITY.HIGH,
      [SEVERITY_LEVELS.CRITICAL]: SEVERITY.CRITICAL
    };
    return mapping[patternSeverity] || SEVERITY.MEDIUM;
  }

  /**
   * Get the higher severity between two severity levels
   * @param {string} current - Current severity
   * @param {string} newSeverity - New severity to compare
   * @returns {string} Higher severity
   * @private
   */
  _getHigherSeverity (current, newSeverity) {
    if (!current) return newSeverity;
    if (!newSeverity) return current;

    const severityOrder = [SEVERITY.LOW, SEVERITY.MEDIUM, SEVERITY.HIGH, SEVERITY.CRITICAL];
    const currentIndex = severityOrder.indexOf(current);
    const newIndex = severityOrder.indexOf(newSeverity);

    return newIndex > currentIndex ? newSeverity : current;
  }

  /**
   * Update validator configuration
   * @param {Object} newConfig - New configuration to merge
   */
  updateConfig (newConfig) {
    this.config = { ...this.config, ...newConfig };
  }

  /**
   * Get current configuration
   * @returns {Object} Current configuration
   */
  getConfig () {
    return { ...this.config };
  }

  /**
   * Safely quote command arguments using shell-quote library
   * @param {Array} args - Array of command and arguments
   * @returns {string} Safely quoted command string
   */
  quote (args) {
    if (!Array.isArray(args)) {
      throw new Error('Arguments must be an array');
    }
    return shellQuote.quote(args);
  }

  /**
   * Parse a command string into an array using shell-quote library
   * @param {string} cmd - Command string to parse
   * @param {Object} env - Optional environment variables
   * @returns {Array} Parsed command array
   */
  parse (cmd, env = {}) {
    if (typeof cmd !== 'string') {
      throw new Error('Command must be a string');
    }
    return shellQuote.parse(cmd, env);
  }

  /**
   * Build a safe command string from command and arguments
   * @param {string} command - The command to execute
   * @param {Array} args - Array of arguments
   * @returns {string} Safely constructed command string
   */
  buildSafeCommand (command, args = []) {
    if (!command || typeof command !== 'string') {
      throw new Error('Command must be a non-empty string');
    }
    return this.quote([command, ...args]);
  }
}

/**
 * Create a command validator with default configuration
 * @param {Object} config - Optional configuration overrides
 * @returns {CommandValidator} New validator instance
 */
function createCommandValidator (config = {}) {
  return new CommandValidator(config);
}

/**
 * Quick validation function for simple use cases
 * @param {string} command - Command to validate
 * @param {Object} config - Optional configuration
 * @returns {Promise<Object>} Validation result
 */
async function validateCommand (command, config = {}) {
  const validator = new CommandValidator(config);
  return await validator.validate(command);
}

/**
 * Quick sanitization function for simple use cases
 * @param {string} command - Command to sanitize
 * @param {Object} config - Optional configuration
 * @returns {Promise<Object>} Sanitization result
 */
async function sanitizeCommand (command, config = {}) {
  const validator = new CommandValidator(config);
  return await validator.sanitize(command);
}

module.exports = {
  CommandValidator,
  createCommandValidator,
  validateCommand,
  sanitizeCommand,
  SEVERITY,
  DEFAULT_CONFIG,
  SHELL_METACHARACTERS,
  INJECTION_PATTERNS
};
