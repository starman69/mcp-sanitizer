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
const dns = require('dns');
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

  assertNotWindowsSystemPath(safePath);
  assertNotSensitivePath(normalizedPath);

  // Use path-is-inside to check if the path tries to escape a safe directory
  // Define safe root directories
  // GHSA-rc4x-x73r-6v9w FIX: cwd=/ would make every absolute path safe
  const cwd = process.cwd();
  const safeRoots = ['/tmp', '/var/tmp', './uploads', './data'];
  if (path.parse(cwd).root !== cwd) safeRoots.push(cwd);

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
 * GHSA-rc4x-x73r-6v9w FIX: enforce contextSettings.filePath confinement options.
 * @param {string} normalizedPath - Path already normalized by the unified parser
 * @param {Object} [config] - { allowAbsolutePaths, allowedDirectories, blockedDirectories }
 */
function assertPathConfinement (normalizedPath, config = {}) {
  const { allowAbsolutePaths, allowedDirectories = [], blockedDirectories = [] } = config;
  const insideAny = (dirs, foldCase) => dirs.some(dir => isInsideDirectory(normalizedPath, dir, foldCase));
  // '*' allows any path, or blocks any path with a directory part.
  const hasDirectory = /[\\/]/.test(path.normalize(normalizedPath));

  if ((blockedDirectories.includes('*') && hasDirectory) || insideAny(blockedDirectories, true)) {
    throw new Error('Path is inside a blocked directory');
  }
  if (allowedDirectories.length > 0 && !allowedDirectories.includes('*') && !insideAny(allowedDirectories, false)) {
    throw new Error('Path is outside the allowed directories');
  }
  if (allowAbsolutePaths === false && path.isAbsolute(normalizedPath) && allowedDirectories.length === 0) {
    throw new Error('Absolute paths are not allowed');
  }
  if (!path.isAbsolute(normalizedPath)) {
    // A relative path is only as safe as the cwd it resolves against
    const resolved = path.resolve(normalizedPath);
    if (SYSTEM_DIRECTORIES.some(dir => isInsideDirectory(resolved, dir, true))) {
      throw new Error('Path resolves into a system directory');
    }
    const cwd = process.cwd();
    const explicitlyAllowed = allowedDirectories.filter(dir => dir !== '*');
    if (path.parse(cwd).root === cwd &&
        ![...SCRATCH_DIRECTORIES, ...explicitlyAllowed].some(dir => isInsideDirectory(resolved, dir, false))) {
      throw new Error('Relative path is outside a safe directory (cwd is the filesystem root)');
    }
  }
}

const SYSTEM_DIRECTORIES = ['/etc', '/proc', '/sys', '/dev', '/root', '/boot', '/usr/bin', '/sbin'];
const SCRATCH_DIRECTORIES = ['/tmp', '/var/tmp'];

function isInsideDirectory (filePath, dir, foldCase) {
  const norm = (p) => {
    const s = trimTrailing(path.resolve(p).replace(/\\/g, '/'), '/');
    return foldCase ? s.toLowerCase() : s;
  };
  const target = norm(filePath);
  const base = norm(dir);
  return target === base || target.startsWith(base + '/');
}

/** Remove trailing characters in `chars` without a regex (avoids polynomial backtracking). */
function trimTrailing (str, chars) {
  let end = str.length;
  while (end > 0 && chars.includes(str[end - 1])) end--;
  return str.slice(0, end);
}

// Directory or file names that hold credentials; `.env.*` is matched separately.
// Audit FIX: added .git (hooks run code), shell history, key files and more credential stores.
const SENSITIVE_PATH_SEGMENTS = new Set([
  '.ssh', '.aws', '.gnupg', '.kube', '.config', '.docker',
  '.npmrc', '.netrc', '.env', '.git-credentials',
  '.git', '.azure', '.terraform.d', '.envrc', '.pgpass', '.my.cnf',
  '.htpasswd', '.vault-token', '.pypirc', '.s3cfg', '.boto',
  '.bash_history', '.zsh_history', '.psql_history', '.mysql_history',
  'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519'
]);

// Windows system directories (first segment after the drive), incl. 8.3 short names.
const WINDOWS_SYSTEM_DIRS = new Set([
  'windows', 'system32', 'program files', 'program files (x86)', 'programdata'
]);

/**
 * Audit FIX: block Windows system directories on any drive, including 8.3 short
 * names (WINDOW~1) and trailing dots/spaces, and drive-relative paths (C:foo).
 * @param {string} safePath - Path already normalized by the unified parser
 * @throws {Error} - If the path targets a Windows system directory or is drive-relative
 */
function assertNotWindowsSystemPath (safePath) {
  if (!/^[a-z]:/i.test(safePath)) return;
  if (!/^[a-z]:[\\/]/i.test(safePath)) {
    throw new Error('Drive-relative Windows paths are not allowed');
  }
  // Resolve `.`/`..` and skip segments Windows reduces to nothing (`D:\.\Windows`, `E:\ \Windows`).
  const first = path.win32.normalize(safePath).slice(2).split(/[\\/]/)
    .map(s => trimTrailing(s.split(':')[0], '. ').toLowerCase())
    .find(Boolean) || '';
  if (WINDOWS_SYSTEM_DIRS.has(first) || /^(window|progra)~\d+$/.test(first)) {
    throw new Error(`Access to system directory not allowed: ${first}`);
  }
}

/**
 * GHSA-7w82-6f9j-v9jp FIX: Block sensitive config files/dirs (SSH keys, cloud
 * credentials, tokens) wherever they sit. Shared by every file-path entry point
 * (GHSA-v25x-53wq-6r99 FIX: validators/file-path.js never ran this check).
 *
 * GHSA-6xj4-4chr-656w FIX: match whole path segments, not `/`-prefixed
 * substrings, so a sensitive first segment (`.env`, `.ssh/id_rsa`) is caught.
 * @param {string} normalizedPath - Path already normalized by the unified parser
 * @throws {Error} - If the path targets a sensitive configuration location
 */
function assertNotSensitivePath (normalizedPath) {
  const segments = normalizedPath.toLowerCase().split(/[\\/]+/)
    // Windows ignores trailing dots/spaces and `:stream` suffixes (`.env.`, `.env::$DATA`).
    .map(s => trimTrailing(s.split(':')[0], '. '));
  if (segments.some(s => SENSITIVE_PATH_SEGMENTS.has(s) || /^\.env\./.test(s))) {
    throw new Error('Access to sensitive configuration path not allowed');
  }
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

// Schemes whose URLs legitimately have no host.
const HOSTLESS_PROTOCOLS = new Set(['file', 'mailto', 'tel', 'urn', 'data']);

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

  // Audit FIX: a hostless URL (mcp:\\127.0.0.1/, mcp:@169.254.169.254) skips the
  // location check but a lenient consumer may still find a host in it.
  if (!parsedUrl.hostname && !HOSTLESS_PROTOCOLS.has(protocol)) {
    throw new Error('URL has no host');
  }
  if (parsedUrl.username || parsedUrl.password) {
    throw new Error('Credentials in URL are not allowed');
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

// Name suffixes that only resolve on private networks (RFC 6762, 8375, 6761 §6.3
// and common unreserved internal TLDs). Includes GCP `metadata.google.internal`.
const INTERNAL_NAME_SUFFIXES = [
  '.internal', '.local', '.localdomain', '.home.arpa', '.lan', '.corp'
];
// Single-label cloud metadata aliases resolved via the DNS search path.
const INTERNAL_NAMES = new Set(['metadata', 'instance-data']);

/**
 * Canonicalize a host as WHATWG does for http (numeric IPv4 forms, %-decoding).
 * @param {string} hostname - Lowercased host without brackets
 * @returns {(string|null)} Canonical hostname, or null if invalid
 */
function canonicalizeSpecialHost (hostname) {
  if (!hostname || /[/?#@\\\s]/.test(hostname)) return null;
  try {
    return new URL(`http://${hostname}/`).hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '');
  } catch (e) {
    return null;
  }
}

/**
 * Classify a URL hostname as a restricted location. Shared by every URL entry
 * point (GHSA-v25x-53wq-6r99 FIX: validators/url.js had its own weaker copy).
 * @param {string} rawHostname - `URL.hostname` (brackets allowed)
 * @returns {{hostname: string, category: (string|null)}} - 'localhost',
 *   'loopback', 'unspecified', 'private', 'link-local', 'reserved',
 *   'internal-name', 'invalid', or null
 */
function classifyHost (rawHostname) {
  // Normalize: strip IPv6 brackets and a trailing dot (FQDN root) before checks.
  const hostname = String(rawHostname)
    .toLowerCase()
    .replace(/^\[|\]$/g, '')
    .replace(/\.$/, '');

  // localhost and any *.localhost name — regardless of port.
  if (hostname === 'localhost' || hostname.endsWith('.localhost')) {
    return { hostname, category: 'localhost' };
  }

  const ipVersion = net.isIP(hostname);

  // GHSA-f8hw-8j7g-r466 FIX: non-special schemes (mcp://) leave hosts like
  // 2852039166 or 0x7f000001 uncanonicalized; classify the http form too.
  if (ipVersion === 0) {
    const canonical = canonicalizeSpecialHost(hostname);
    // Not a valid host (e.g. `%00`): a consumer could decode it to a restricted address
    if (hostname && !canonical) return { hostname, category: 'invalid' };
    if (canonical !== hostname) {
      const result = classifyHost(canonical);
      if (result.category) return result;
    }
  }

  // IPv4 literal — classify directly.
  if (ipVersion === 4) {
    return { hostname, category: classifyIPv4(hostname.split('.').map(Number)) };
  }

  // IPv6 — classify the address family, then any embedded IPv4 payload.
  if (ipVersion === 6) {
    const canonical = expandIPv6(hostname);
    if (!canonical) return { hostname, category: null };
    if (canonical === '0000:0000:0000:0000:0000:0000:0000:0001') {
      return { hostname, category: 'loopback' };
    }
    if (canonical === '0000:0000:0000:0000:0000:0000:0000:0000') {
      return { hostname, category: 'unspecified' };
    }
    const groups = canonical.split(':');
    // Link-local fe80::/10 (fe80–febf).
    if (groups[0] >= 'fe80' && groups[0] <= 'febf') {
      return { hostname, category: 'link-local' };
    }
    // Unique-local fc00::/7 and deprecated site-local fec0::/10.
    if ((groups[0] >= 'fc00' && groups[0] <= 'fdff') ||
        (groups[0] >= 'fec0' && groups[0] <= 'feff')) {
      return { hostname, category: 'private' };
    }
    // Multicast ff00::/8.
    if (groups[0].startsWith('ff')) {
      return { hostname, category: 'reserved' };
    }
    // IPv4-mapped (::ffff:a.b.c.d), IPv4-compatible (::a.b.c.d) and NAT64
    // (64:ff9b::a.b.c.d) carry the IPv4 in the last 32 bits; 6to4
    // (2002:aabb:ccdd::) carries it in groups 1–2. Node re-encodes the IPv4 as
    // hex, so recover it from the canonical form and apply the IPv4 checks.
    const zeros = (from, to) => groups.slice(from, to).every(g => g === '0000');
    // GHSA-3pp5-crfq-6grr FIX: also IPv4-translated ::ffff:0:a.b.c.d (RFC 2765).
    if ((zeros(0, 5) && (groups[5] === 'ffff' || groups[5] === '0000')) ||
        (zeros(0, 4) && groups[4] === 'ffff' && groups[5] === '0000') ||
        (groups[0] === '0064' && groups[1] === 'ff9b' && zeros(2, 6))) {
      return { hostname, category: classifyEmbeddedIPv4(groups[6], groups[7]) };
    }
    // NAT64 local-use 64:ff9b:1::/48 and Teredo 2001::/32 can reach internal IPv4.
    if ((groups[0] === '0064' && groups[1] === 'ff9b' && groups[2] === '0001') ||
        (groups[0] === '2001' && groups[1] === '0000')) {
      return { hostname, category: 'reserved' };
    }
    if (groups[0] === '2002') {
      return { hostname, category: classifyEmbeddedIPv4(groups[1], groups[2]) };
    }
    return { hostname, category: null };
  }

  // GHSA-qvp2-8q5w-gcfp FIX: names that can only resolve internally.
  if (INTERNAL_NAMES.has(hostname) ||
      INTERNAL_NAME_SUFFIXES.some(suffix => hostname.endsWith(suffix))) {
    return { hostname, category: 'internal-name' };
  }

  return { hostname, category: null };
}

/**
 * Classify an IPv4 address embedded in two IPv6 hex groups.
 * @param {string} hiHex - Group holding octets a.b
 * @param {string} loHex - Group holding octets c.d
 * @returns {string|null} - Restricted category, or null if publicly routable
 */
function classifyEmbeddedIPv4 (hiHex, loHex) {
  const hi = parseInt(hiHex, 16);
  const lo = parseInt(loHex, 16);
  return classifyIPv4([(hi >> 8) & 0xff, hi & 0xff, (lo >> 8) & 0xff, lo & 0xff]);
}

/**
 * Classify IPv4 octets; shared by literal IPv4 and embedded IPv4 in IPv6.
 * @param {number[]} o - Four octets [a, b, c, d]
 * @returns {string|null} - Restricted category, or null if publicly routable
 */
function classifyIPv4 (o) {
  // Loopback 127.0.0.0/8 and unspecified 0.0.0.0/8.
  if (o[0] === 127) return 'loopback';
  if (o[0] === 0) return 'unspecified';
  // RFC 1918 private ranges and CGNAT shared space 100.64.0.0/10.
  if (o[0] === 10 ||
      (o[0] === 192 && o[1] === 168) ||
      (o[0] === 172 && o[1] >= 16 && o[1] <= 31) ||
      (o[0] === 100 && o[1] >= 64 && o[1] <= 127)) {
    return 'private';
  }
  // Link-local 169.254.0.0/16 (includes cloud metadata 169.254.169.254).
  if (o[0] === 169 && o[1] === 254) return 'link-local';
  // IETF protocol assignments 192.0.0.0/24, benchmarking 198.18.0.0/15,
  // multicast 224.0.0.0/4 and reserved/broadcast 240.0.0.0/4.
  // GHSA-3pp5-crfq-6grr FIX: 6to4 relay anycast 192.88.99.0/24, Azure WireServer 168.63.129.16.
  if ((o[0] === 192 && o[1] === 0 && o[2] === 0) ||
      (o[0] === 192 && o[1] === 88 && o[2] === 99) ||
      (o[0] === 168 && o[1] === 63 && o[2] === 129 && o[3] === 16) ||
      (o[0] === 198 && (o[1] === 18 || o[1] === 19)) ||
      o[0] >= 224) {
    return 'reserved';
  }
  return null;
}

/**
 * Throw if a hostname is excluded by `blockedDomains` or, when `allowedDomains`
 * is non-empty, not covered by it. An entry matches itself and its subdomains.
 * The allowlist only narrows: it never admits a restricted `classifyHost` category.
 * @param {string} hostname - Normalized hostname (from `classifyHost`)
 * @param {Object} [options] - `{ blockedDomains, allowedDomains }`
 * @throws {Error} - If the hostname is not permitted
 */
function assertDomainAllowed (hostname, { blockedDomains = [], allowedDomains = [] } = {}) {
  const matches = (entry) => {
    const domain = String(entry).toLowerCase().replace(/^\*?\./, '').replace(/\.$/, '');
    return domain !== '' && (hostname === domain || hostname.endsWith('.' + domain));
  };
  if (blockedDomains.some(matches)) {
    throw new Error(`URL host is in blockedDomains: ${hostname}`);
  }
  if (allowedDomains.length > 0 && !allowedDomains.some(matches)) {
    throw new Error(`URL host is not in allowedDomains: ${hostname}`);
  }
}

/**
 * Validate URL against restricted locations (localhost, loopback, private,
 * link-local, reserved addresses and internal-only names). Blocks
 * unconditionally — there is no escape hatch — so the sanitizer fails closed
 * for SSRF targets. String-level only: a public name that resolves to a
 * private address needs `resolveAndValidateURL`.
 *
 * GHSA-4mfg-r38w-w8fg FIX: previously (1) localhost was only blocked when no
 * explicit port was present, and (2) bracketed IPv6 hostnames (`[::1]`,
 * `[fe80::1]`) never matched the string checks. Both gaps allowed SSRF to
 * internal services. The hostname is now bracket-stripped and classified by
 * actual address family/range (see `classifyHost`), covering IPv4-mapped IPv6
 * and additional loopback/private encodings.
 *
 * @param {string|URL} url - The URL to validate (string or URL object)
 * @param {Object} [options] - `{ blockedDomains, allowedDomains }`
 * @throws {Error} - If URL points to restricted location
 */
function validateURLLocation (url, options = {}) {
  let parsedUrl = url;

  if (typeof url === 'string') {
    parsedUrl = new URL(url);
  } else if (!(url instanceof URL)) {
    throw new Error('URL must be a string or URL object');
  }

  const { hostname, category } = classifyHost(parsedUrl.hostname);
  if (category === 'localhost') {
    throw new Error('URL points to localhost');
  }
  if (category === 'link-local') {
    throw new Error(`URL points to link-local address: ${hostname}`);
  }
  if (category === 'reserved') {
    throw new Error(`URL points to reserved address: ${hostname}`);
  }
  if (category === 'internal-name') {
    throw new Error(`URL points to internal hostname: ${hostname}`);
  }
  if (category === 'invalid') {
    throw new Error(`URL has an invalid hostname: ${hostname}`);
  }
  if (category) {
    throw new Error(`URL points to private IP range: ${hostname}`);
  }
  assertDomainAllowed(hostname, options);
}

/**
 * Resolve a hostname to every address it maps to and classify each one.
 * @param {string} hostname - Normalized, non-IP hostname
 * @param {Function} [lookup] - `dns.promises.lookup`-compatible (for tests)
 * @returns {Promise<Array<{address: string, family: number, category: (string|null)}>>}
 * @throws {Error} - If resolution fails or returns no addresses
 */
async function resolveHost (hostname, lookup = dns.promises.lookup) {
  const addresses = await lookup(hostname, { all: true, verbatim: true });
  if (!addresses || addresses.length === 0) {
    throw new Error(`DNS lookup returned no addresses for ${hostname}`);
  }
  return addresses.map(({ address, family }) =>
    ({ address, family, category: classifyHost(address).category }));
}

/**
 * GHSA-qvp2-8q5w-gcfp FIX: validate a URL and every address its hostname
 * resolves to, so a public DNS alias for a private address (`10.0.0.5.nip.io`)
 * is rejected. Connect to the returned `address` (e.g. via a custom `lookup`
 * on the HTTP agent) so a later DNS change cannot redirect the request.
 *
 * @param {string} url - The URL to validate
 * @param {Object} [options] - `{ allowedProtocols, blockedDomains, allowedDomains, lookup }`
 * @returns {Promise<{url: URL, address: string, family: number}>} - Checked URL and pinned address
 * @throws {Error} - If the URL or any resolved address is restricted
 */
async function resolveAndValidateURL (url, options = {}) {
  const parsedUrl = validateURL(url, options.allowedProtocols);
  validateURLLocation(parsedUrl, options);

  const { hostname } = classifyHost(parsedUrl.hostname);
  const family = net.isIP(hostname);
  if (family) {
    return { url: parsedUrl, address: hostname, family };
  }

  const resolved = await resolveHost(hostname, options.lookup);
  const restricted = resolved.find(r => r.category);
  if (restricted) {
    throw new Error(`URL host ${hostname} resolves to ${restricted.category} address: ${restricted.address}`);
  }
  return { url: parsedUrl, address: resolved[0].address, family: resolved[0].family };
}

// GHSA-vwjq-wx58-g4qr FIX: one list for every command entry point, matched on
// the normalized basename so `/bin/rm`, `RM.EXE` and `python3.11` are caught.
const DANGEROUS_COMMANDS = new Set([
  'rm', 'del', 'format', 'mkfs', 'dd',
  'nc', 'ncat', 'netcat', 'socat', 'telnet', 'ssh',
  'curl', 'wget',
  'sh', 'bash', 'dash', 'zsh', 'ksh', 'csh', 'tcsh', 'ash', 'fish', 'busybox',
  'cmd', 'powershell', 'pwsh',
  'python', 'node', 'perl', 'ruby', 'php', 'lua',
  'sudo', 'su', 'doas', 'chmod', 'chown'
]);

// Commands that run their arguments as another command.
const COMMAND_WRAPPERS = new Set([
  'env', 'exec', 'xargs', 'nohup', 'timeout', 'nice', 'ionice', 'stdbuf',
  'time', 'command', 'builtin', 'setsid', 'chroot', 'strace', 'sudo', 'doas'
]);

/**
 * Normalize a command token to the program name a shell would run.
 * @param {string} token - Command token (may include a path, quotes or extension)
 * @returns {string} - Lowercase basename without a Windows executable extension
 */
function commandBaseName (token) {
  return String(token)
    .trim()
    .replace(/^["']+|["']+$/g, '')
    .split(/[\\/]/)
    .pop()
    .toLowerCase()
    .replace(/\.(exe|com|bat|cmd|ps1)$/, '');
}

/**
 * Whether a command token names a program in `DANGEROUS_COMMANDS`, ignoring
 * path, case, executable extension and version suffix.
 * @param {string} token - Command token
 * @param {Iterable<string>} [list] - Names to match (defaults to `DANGEROUS_COMMANDS`)
 * @returns {boolean}
 */
function isDangerousCommand (token, list = DANGEROUS_COMMANDS) {
  const name = commandBaseName(token);
  if (!name) return false;
  const names = list instanceof Set ? list : new Set(Array.from(list, n => String(n).toLowerCase()));
  let end = name.length; // strip a version suffix (python3.11 -> python) without a backtracking regex
  while (end > 0 && '0123456789._-'.includes(name[end - 1])) end--;
  const bare = name.slice(0, end);
  return names.has(name) || (bare !== '' && names.has(bare)) ||
    (names.has('mkfs') && /^mkfs(\.|$)/.test(name));
}

/**
 * First dangerous word in a command. The program (and whatever a wrapper such as
 * `env` or `timeout 5` runs) is matched by basename; other words only by bare name,
 * so `rm` as an argument is caught but a path like `/home/user/node` is not.
 * @param {string[]} words - Command words, program first
 * @returns {string|undefined}
 */
function findDangerousWord (words) {
  let commandPosition = true;
  for (const word of words) {
    const isPath = /[\\/]/.test(word);
    if (commandPosition) {
      if (isDangerousCommand(word)) return word;
      if (/^-|^\d+$|=/.test(word)) continue; // wrapper options: -i, 5, VAR=1
      commandPosition = COMMAND_WRAPPERS.has(commandBaseName(word));
    } else if (!isPath && isDangerousCommand(word)) {
      return word;
    }
  }
  return undefined;
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
    // shell-quote drops unquoted backslashes, so also check the raw words (C:\...\cmd.exe).
    const rawWords = safeCommand.split(/\s+/).filter(Boolean);
    const dangerous = findDangerousWord(rawWords) ||
      findDangerousWord(parsed.filter(t => typeof t === 'string'));
    if (dangerous) {
      throw new Error(`Dangerous command detected: ${dangerous}`);
    }

    // Check for command injection by examining parsed tokens
    for (const token of parsed) {
      if (typeof token === 'object') {
        // Objects indicate shell operators, redirections, or expansions - potential injection
        throw new Error('Command contains shell injection patterns');
      }

      if (typeof token === 'string') {
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
  assertNotSensitivePath,
  assertNotWindowsSystemPath,
  assertPathConfinement,
  validateFileExtension,
  validateURL,
  validateURLLocation,
  classifyHost,
  assertDomainAllowed,
  resolveHost,
  resolveAndValidateURL,
  validateCommand,
  isDangerousCommand,
  commandBaseName,
  DANGEROUS_COMMANDS,
  COMMAND_WRAPPERS,
  validateOptions,
  validateRange,
  validateArrayOfType,
  combineValidators
};
