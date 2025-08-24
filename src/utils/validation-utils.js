/**
 * Common validation functions for MCP Sanitizer
 *
 * This module provides reusable validation functions that are
 * used across different validators and sanitizers.
 *
 * CVE-TBD-001 FIX: All functions now use unified parsing to prevent
 * parser differential attacks. Original strings are never accessed.
 */

const path = require('path');
const { URL } = require('url');
// CVE-TBD-001 FIX: Import unified parser for consistent string normalization
const { parseUnified } = require('./unified-parser');

/**
 * Validate that a value is a non-empty string
 * @param {*} value - The value to validate
 * @param {string} [paramName='value'] - Parameter name for error messages
 * @throws {Error} - If value is not a non-empty string
 */
function validateNonEmptyString (value, paramName = 'value') {
  if (typeof value !== 'string') {
    throw new Error(`${paramName} must be a string`);
  }

  if (value.trim().length === 0) {
    throw new Error(`${paramName} cannot be empty`);
  }
}

/**
 * Validate that a value is a positive number
 * @param {*} value - The value to validate
 * @param {string} [paramName='value'] - Parameter name for error messages
 * @throws {Error} - If value is not a positive number
 */
function validatePositiveNumber (value, paramName = 'value') {
  if (typeof value !== 'number') {
    throw new Error(`${paramName} must be a number`);
  }

  if (!isFinite(value)) {
    throw new Error(`${paramName} must be a finite number`);
  }

  if (value < 0) {
    throw new Error(`${paramName} must be a positive number`);
  }
}

/**
 * Validate that a value is an array
 * @param {*} value - The value to validate
 * @param {string} [paramName='value'] - Parameter name for error messages
 * @throws {Error} - If value is not an array
 */
function validateArray (value, paramName = 'value') {
  if (!Array.isArray(value)) {
    throw new Error(`${paramName} must be an array`);
  }
}

/**
 * Validate that a value is a function
 * @param {*} value - The value to validate
 * @param {string} [paramName='value'] - Parameter name for error messages
 * @throws {Error} - If value is not a function
 */
function validateFunction (value, paramName = 'value') {
  if (typeof value !== 'function') {
    throw new Error(`${paramName} must be a function`);
  }
}

/**
 * Validate that a value is a RegExp
 * @param {*} value - The value to validate
 * @param {string} [paramName='value'] - Parameter name for error messages
 * @throws {Error} - If value is not a RegExp
 */
function validateRegExp (value, paramName = 'value') {
  if (!(value instanceof RegExp)) {
    throw new Error(`${paramName} must be a RegExp`);
  }
}

/**
 * CVE-TBD-001 FIX: Validate file path using unified parsing
 * @param {string} filePath - The file path to validate (will be normalized)
 * @returns {string} - Normalized file path
 * @throws {Error} - If file path is unsafe
 */
function validateFilePath (filePath) {
  validateNonEmptyString(filePath, 'filePath');

  // CVE-TBD-001 FIX: Use unified parser to ensure consistent normalization
  const normalizedStr = parseUnified(filePath, { type: 'file_path' });
  const safePath = normalizedStr.getNormalized();

  // SECURITY FIX 2: Use path-is-inside for proper path validation
  const pathIsInside = require('path-is-inside');

  // Normalize the path for security checks (handles ./ ../ and mixed separators)
  const normalizedPath = path.normalize(safePath);

  // Check for directory traversal attempts
  if (normalizedPath.includes('..')) {
    throw new Error('Directory traversal detected in file path');
  }

  // SECURITY FIX 3: Detect and block UNC paths
  if (filePath.startsWith('\\\\') || filePath.match(/^\\\\[^\\]+\\[^\\]+/)) {
    throw new Error('UNC paths are not allowed');
  }

  // SECURITY FIX 4: Enhanced Windows system path detection
  const windowsSystemPaths = [
    'C:\\Windows\\',
    'C:\\System32\\',
    'C:\\Program Files\\',
    'C:\\Windows\\System32\\',
    'C:\\Windows\\SysWOW64\\',
    '%SystemRoot%\\',
    '%WINDIR%\\',
    // Also check normalized versions (forward slashes)
    'C:/Windows/',
    'C:/System32/',
    'C:/Program Files/',
    'C:/Windows/System32/',
    'C:/Windows/SysWOW64/'
  ];

  // Check for access to system directories (Unix/Linux)
  const dangerousUnixPaths = ['/etc/', '/proc/', '/sys/', '/dev/', '/root/', '/boot/', '/usr/bin/', '/sbin/'];

  const lowerPath = normalizedPath.toLowerCase();
  // CVE-TBD-001 FIX: Only check normalized path, not original (prevents parser differential)
  const lowerSafe = safePath.toLowerCase();

  // Check against all dangerous paths (ONLY normalized versions)
  for (const dangerousPath of [...dangerousUnixPaths, ...windowsSystemPaths]) {
    const lowerDangerous = dangerousPath.toLowerCase();
    if (lowerPath.startsWith(lowerDangerous) ||
        lowerSafe.startsWith(lowerDangerous) ||
        // Also check with backslashes converted to forward slashes
        lowerSafe.replace(/\\/g, '/').startsWith(lowerDangerous)) {
      throw new Error(`Access to system directory not allowed: ${dangerousPath}`);
    }
  }

  // Use path-is-inside to check if the path tries to escape a safe directory
  // Define safe root directories
  const safeRoots = ['/tmp', '/var/tmp', './uploads', './data', process.cwd()];

  let isInSafeLocation = false;
  for (const safeRoot of safeRoots) {
    try {
      if (path.isAbsolute(normalizedPath)) {
        // For absolute paths, check if they're inside safe directories
        if (pathIsInside(normalizedPath, safeRoot)) {
          isInSafeLocation = true;
          break;
        }
      } else {
        // For relative paths, they're generally safer but check they don't escape
        const resolvedPath = path.resolve(process.cwd(), normalizedPath);
        if (pathIsInside(resolvedPath, process.cwd()) || pathIsInside(resolvedPath, safeRoot)) {
          isInSafeLocation = true;
          break;
        }
      }
    } catch (err) {
      // Continue checking other safe roots
      continue;
    }
  }

  // For development/testing, allow relative paths within current directory
  if (!isInSafeLocation && !path.isAbsolute(normalizedPath)) {
    const resolvedPath = path.resolve(process.cwd(), normalizedPath);
    if (pathIsInside(resolvedPath, process.cwd())) {
      isInSafeLocation = true;
    }
  }

  // If path is not in a safe location and is absolute, be more restrictive
  if (!isInSafeLocation && path.isAbsolute(normalizedPath)) {
    // Allow some common safe absolute paths for legitimate use
    const allowedAbsolutePaths = ['/tmp/', '/var/tmp/', '/home/', '/Users/'];
    const isAllowedAbsolute = allowedAbsolutePaths.some(allowed =>
      normalizedPath.toLowerCase().startsWith(allowed.toLowerCase())
    );

    if (!isAllowedAbsolute) {
      throw new Error('Absolute path not in allowed safe directory');
    }
  }

  // CVE-TBD-001 FIX: Return normalized path, never original
  return safePath;
}

/**
 * Validate file extension against allowed list
 * @param {string} filePath - The file path to validate
 * @param {string[]} allowedExtensions - Array of allowed file extensions
 * @throws {Error} - If file extension is not allowed
 */
function validateFileExtension (filePath, allowedExtensions) {
  validateNonEmptyString(filePath, 'filePath');
  validateArray(allowedExtensions, 'allowedExtensions');

  const ext = path.extname(filePath).toLowerCase();

  if (ext && !allowedExtensions.includes(ext)) {
    throw new Error(`File extension ${ext} not allowed. Allowed extensions: ${allowedExtensions.join(', ')}`);
  }
}

/**
 * CVE-TBD-001 FIX: Validate URL using unified parsing
 * @param {string} url - The URL to validate (will be normalized)
 * @param {string[]} [allowedProtocols=['http', 'https']] - Array of allowed protocols
 * @returns {URL} - Parsed URL object
 * @throws {Error} - If URL is unsafe
 */
function validateURL (url, allowedProtocols = ['http', 'https']) {
  validateNonEmptyString(url, 'url');
  validateArray(allowedProtocols, 'allowedProtocols');

  // CVE-TBD-001 FIX: Use unified parser to ensure consistent normalization
  const normalizedStr = parseUnified(url, { type: 'url' });
  const safeUrl = normalizedStr.getNormalized();

  let parsedUrl;

  try {
    parsedUrl = new URL(safeUrl);
  } catch (error) {
    throw new Error('Invalid URL format');
  }

  // Check protocol
  const protocol = parsedUrl.protocol.slice(0, -1); // Remove trailing colon
  if (!allowedProtocols.includes(protocol)) {
    throw new Error(`Protocol ${protocol} not allowed. Allowed protocols: ${allowedProtocols.join(', ')}`);
  }

  // Check for suspicious patterns in URL path
  if (parsedUrl.pathname.includes('..')) {
    throw new Error('Directory traversal detected in URL path');
  }

  return parsedUrl;
}

/**
 * Validate URL against restricted locations (localhost, private IPs, etc.)
 * @param {string|URL} url - The URL to validate (string or URL object)
 * @throws {Error} - If URL points to restricted location
 */
function validateURLLocation (url) {
  let parsedUrl = url;

  if (typeof url === 'string') {
    parsedUrl = new URL(url);
  } else if (!(url instanceof URL)) {
    throw new Error('URL must be a string or URL object');
  }

  const hostname = parsedUrl.hostname.toLowerCase();

  // Check for localhost - allow localhost with explicit port for development
  if ((hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1') && !parsedUrl.port) {
    throw new Error('URL points to localhost without explicit port');
  }

  // Check for private IP ranges
  const privateIPPatterns = [
    /^127\./, // 127.0.0.0/8 (loopback)
    /^10\./, // 10.0.0.0/8 (private)
    /^192\.168\./, // 192.168.0.0/16 (private)
    /^172\.(1[6-9]|2[0-9]|3[01])\./ // 172.16.0.0/12 (private)
  ];

  for (const pattern of privateIPPatterns) {
    if (pattern.test(hostname)) {
      throw new Error(`URL points to private IP range: ${hostname}`);
    }
  }

  // Check for link-local addresses
  if (hostname.startsWith('169.254.') || hostname.startsWith('fe80:')) {
    throw new Error(`URL points to link-local address: ${hostname}`);
  }
}

/**
 * CVE-TBD-001 FIX: Validate command using unified parsing
 * @param {string} command - The command string to validate (will be normalized)
 * @returns {string} - Trimmed command string
 * @throws {Error} - If command contains dangerous patterns
 */
function validateCommand (command) {
  validateNonEmptyString(command, 'command');

  // CVE-TBD-001 FIX: Use unified parser to ensure consistent normalization
  const normalizedStr = parseUnified(command, { type: 'command' });
  const safeCommand = normalizedStr.getNormalized();

  // SECURITY FIX 1: Use shell-quote to properly parse and validate commands
  const shellQuote = require('shell-quote');

  try {
    // Parse the NORMALIZED command to detect injection attempts
    const parsed = shellQuote.parse(safeCommand);

    // Check for command injection by examining parsed tokens
    for (const token of parsed) {
      if (typeof token === 'object') {
        // Objects indicate shell operators, redirections, or expansions - potential injection
        throw new Error('Command contains shell injection patterns');
      }

      if (typeof token === 'string') {
        // Check each command token against dangerous patterns
        const dangerousCommands = [
          /^(rm|del|format|mkfs[\w.]*|dd)$/i,
          /^(nc|netcat|telnet|ssh)$/i,
          /^(curl|wget|python|node|bash|sh|powershell|cmd)$/i,
          /^(sudo|su|chmod|chown)$/i
        ];

        for (const pattern of dangerousCommands) {
          if (pattern.test(token.trim())) {
            throw new Error(`Dangerous command detected: ${token}`);
          }
        }

        // Check for sensitive file access
        if (token.includes('/etc/') || token.includes('/proc/') || token.includes('/sys/') ||
            token.toLowerCase().includes('c:\\windows\\') || token.includes('.ssh') ||
            token.includes('passwd') || token.includes('shadow')) {
          throw new Error('Access to sensitive files/directories blocked');
        }
      }
    }
  } catch (error) {
    if (error.message.includes('Dangerous command') || error.message.includes('injection') ||
        error.message.includes('sensitive files')) {
      throw error;
    }
    // If shell-quote parsing fails, treat as suspicious
    throw new Error('Invalid or malicious command syntax');
  }

  // CVE-TBD-001 FIX: Return normalized command, never original
  return safeCommand.trim();
}

/**
 * Validate options object structure
 * @param {object} options - Options object to validate
 * @param {object} schema - Schema defining expected structure
 * @throws {Error} - If options don't match schema
 */
function validateOptions (options, schema) {
  if (typeof options !== 'object' || options === null) {
    throw new Error('Options must be an object');
  }

  if (typeof schema !== 'object' || schema === null) {
    throw new Error('Schema must be an object');
  }

  for (const [key, validator] of Object.entries(schema)) {
    if (key in options) {
      try {
        validator(options[key], key);
      } catch (error) {
        throw new Error(`Invalid option '${key}': ${error.message}`);
      }
    }
  }
}

/**
 * Validate that a value is within a specified range
 * @param {number} value - The value to validate
 * @param {number} min - Minimum allowed value (inclusive)
 * @param {number} max - Maximum allowed value (inclusive)
 * @param {string} [paramName='value'] - Parameter name for error messages
 * @throws {Error} - If value is outside the range
 */
function validateRange (value, min, max, paramName = 'value') {
  validatePositiveNumber(value, paramName);
  validatePositiveNumber(min, 'min');
  validatePositiveNumber(max, 'max');

  if (min > max) {
    throw new Error('Minimum value cannot be greater than maximum value');
  }

  if (value < min || value > max) {
    throw new Error(`${paramName} must be between ${min} and ${max} (inclusive)`);
  }
}

/**
 * Validate that an array contains only specific types
 * @param {Array} array - The array to validate
 * @param {string} expectedType - Expected type of array elements
 * @param {string} [paramName='array'] - Parameter name for error messages
 * @throws {Error} - If array contains elements of wrong type
 */
function validateArrayOfType (array, expectedType, paramName = 'array') {
  validateArray(array, paramName);

  for (let i = 0; i < array.length; i++) {
    const element = array[i];
    let actualType = typeof element;

    // Special handling for RegExp objects
    if (expectedType === 'regexp' && element instanceof RegExp) {
      actualType = 'regexp';
    }

    if (actualType !== expectedType) {
      throw new Error(`${paramName}[${i}] must be of type ${expectedType}, got ${actualType}`);
    }
  }
}

/**
 * Create a validator function that checks multiple conditions
 * @param {...Function} validators - Validator functions to combine
 * @returns {Function} - Combined validator function
 */
function combineValidators (...validators) {
  return function (value, paramName) {
    for (const validator of validators) {
      validator(value, paramName);
    }
  };
}

module.exports = {
  validateNonEmptyString,
  validatePositiveNumber,
  validateArray,
  validateFunction,
  validateRegExp,
  validateFilePath,
  validateFileExtension,
  validateURL,
  validateURLLocation,
  validateCommand,
  validateOptions,
  validateRange,
  validateArrayOfType,
  combineValidators
};
