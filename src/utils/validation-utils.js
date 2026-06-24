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
const net = require('net');
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

  // GHSA-7w82-6f9j-v9jp FIX: Block sensitive user-configuration files/directories
  // regardless of where they sit (home dir, /tmp, cwd, relative paths). These hold
  // SSH keys, cloud credentials, and tokens that must never be exposed via a tool.
  const sensitiveFileFragments = [
    '/.ssh/', '/.aws/', '/.gnupg/', '/.kube/', '/.config/',
    '/.docker/', '/.npmrc', '/.netrc', '/.env', '/.git-credentials'
  ];
  const sensitiveCheckPath = lowerPath.replace(/\\/g, '/');
  for (const fragment of sensitiveFileFragments) {
    if (sensitiveCheckPath.includes(fragment)) {
      throw new Error('Access to sensitive configuration path not allowed');
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
    // GHSA-7w82-6f9j-v9jp FIX: `/home/` and `/Users/` were removed from this
    // allowlist. Whitelisting entire home roots let any absolute path under a
    // user's home directory (e.g. ~/.ssh/id_rsa) pass with blocked=false.
    // Only genuinely shared scratch directories remain allowed by default.
    const allowedAbsolutePaths = ['/tmp/', '/var/tmp/'];
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
 * Expand an IPv6 address (including `::` compression and trailing embedded
 * IPv4) into its canonical 8-group, zero-padded, lowercase form so ranges can
 * be compared reliably. Returns null when the input is not a parseable IPv6.
 * @param {string} addr - IPv6 hostname without surrounding brackets
 * @returns {string|null} - e.g. '0000:0000:0000:0000:0000:0000:0000:0001'
 */
function expandIPv6 (addr) {
  let s = addr;

  // Convert a trailing embedded IPv4 (e.g. ::ffff:127.0.0.1) into two hex groups
  const embedded = s.match(/^(.*:)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (embedded) {
    const octets = embedded[2].split('.').map(Number);
    if (octets.every(n => n >= 0 && n <= 255)) {
      const g1 = ((octets[0] << 8) | octets[1]).toString(16);
      const g2 = ((octets[2] << 8) | octets[3]).toString(16);
      s = `${embedded[1]}${g1}:${g2}`;
    }
  }

  let groups;
  if (s.includes('::')) {
    const parts = s.split('::');
    if (parts.length > 2) return null;
    const head = parts[0] ? parts[0].split(':') : [];
    const tail = parts[1] ? parts[1].split(':') : [];
    const missing = 8 - head.length - tail.length;
    if (missing < 0) return null;
    groups = head.concat(Array(missing).fill('0'), tail);
  } else {
    groups = s.split(':');
  }

  if (groups.length !== 8) return null;
  return groups
    .map(g => (/^[0-9a-f]{1,4}$/.test(g) ? g.padStart(4, '0') : null))
    .map(g => g || 'zzzz') // invalid group -> sentinel that matches no real range
    .join(':');
}

/**
 * Validate URL against restricted locations (localhost, loopback, private and
 * link-local addresses). Blocks unconditionally — there is no escape hatch — so
 * the sanitizer fails closed for SSRF targets.
 *
 * GHSA-4mfg-r38w-w8fg FIX: previously (1) localhost was only blocked when no
 * explicit port was present, and (2) bracketed IPv6 hostnames (`[::1]`,
 * `[fe80::1]`) never matched the string checks. Both gaps allowed SSRF to
 * internal services. The hostname is now bracket-stripped and classified by
 * actual address family/range, covering IPv4-mapped IPv6 and additional
 * loopback/private encodings.
 *
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

  // Normalize: strip IPv6 brackets and a trailing dot (FQDN root) before checks.
  const hostname = parsedUrl.hostname
    .toLowerCase()
    .replace(/^\[|\]$/g, '')
    .replace(/\.$/, '');

  // localhost and any *.localhost name — blocked regardless of port.
  if (hostname === 'localhost' || hostname.endsWith('.localhost')) {
    throw new Error('URL points to localhost');
  }

  const ipVersion = net.isIP(hostname);

  // IPv4 literal — classify directly.
  if (ipVersion === 4) {
    assertPublicIPv4(hostname.split('.').map(Number), hostname);
  }

  // IPv6 — classify the address family, then any IPv4-mapped/compatible payload.
  if (ipVersion === 6) {
    const canonical = expandIPv6(hostname);
    if (canonical) {
      // Loopback (::1) and unspecified (::).
      if (canonical === '0000:0000:0000:0000:0000:0000:0000:0001' ||
          canonical === '0000:0000:0000:0000:0000:0000:0000:0000') {
        throw new Error(`URL points to private IP range: ${hostname}`);
      }
      const firstGroup = canonical.slice(0, 4);
      // Link-local fe80::/10 (fe80–febf).
      if (firstGroup >= 'fe80' && firstGroup <= 'febf') {
        throw new Error(`URL points to link-local address: ${hostname}`);
      }
      // Unique-local fc00::/7 (fc00–fdff).
      if (firstGroup >= 'fc00' && firstGroup <= 'fdff') {
        throw new Error(`URL points to private IP range: ${hostname}`);
      }
      // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d) addresses:
      // the first five groups are zero and the sixth is ffff or zero. Node
      // re-encodes the trailing IPv4 as hex, so recover it from the canonical
      // form and apply the same IPv4 range checks.
      const groups = canonical.split(':');
      if (groups.slice(0, 5).every(g => g === '0000') &&
          (groups[5] === 'ffff' || groups[5] === '0000')) {
        const hi = parseInt(groups[6], 16);
        const lo = parseInt(groups[7], 16);
        assertPublicIPv4([(hi >> 8) & 0xff, hi & 0xff, (lo >> 8) & 0xff, lo & 0xff], hostname);
      }
    }
  }
}

/**
 * Throw if the given IPv4 octets fall in a loopback, unspecified, RFC 1918
 * private, or link-local range. Shared by literal IPv4 and IPv4-mapped IPv6.
 * @param {number[]} o - Four octets [a, b, c, d]
 * @param {string} hostname - Original hostname, for the error message
 * @throws {Error} - If the address is not publicly routable
 */
function assertPublicIPv4 (o, hostname) {
  // Loopback 127.0.0.0/8 and unspecified 0.0.0.0/8.
  if (o[0] === 127 || o[0] === 0) {
    throw new Error(`URL points to private IP range: ${hostname}`);
  }
  // RFC 1918 private ranges.
  if (o[0] === 10 ||
      (o[0] === 192 && o[1] === 168) ||
      (o[0] === 172 && o[1] >= 16 && o[1] <= 31)) {
    throw new Error(`URL points to private IP range: ${hostname}`);
  }
  // Link-local 169.254.0.0/16 (includes cloud metadata 169.254.169.254).
  if (o[0] === 169 && o[1] === 254) {
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
