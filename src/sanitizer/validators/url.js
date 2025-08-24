/**
 * URL Validator for MCP Sanitizer
 *
 * This module provides comprehensive validation and sanitization for URLs,
 * protecting against malicious URLs, SSRF attacks, and invalid protocols.
 *
 * Features:
 * - Protocol validation and restriction
 * - Hostname and IP validation
 * - Private IP and localhost detection
 * - URL structure validation
 * - Query parameter sanitization
 * - Port number validation
 * - Configurable validation rules
 * - Async validation support
 *
 * @example
 * const { URLValidator } = require('./url');
 * const validator = new URLValidator(config);
 *
 * const result = await validator.validate('https://example.com/path');
 * if (result.isValid) {
 *   console.log('Sanitized URL:', result.sanitized);
 * } else {
 *   console.error('Validation failed:', result.warnings);
 * }
 */

const { URL } = require('url')
// const { validationUtils } = require('../../utils') // Unused - commented to fix ESLint
const { detectAllPatterns, SEVERITY_LEVELS } = require('../../patterns')
const validator = require('validator')
const {
  detectMultipleUrlEncoding,
  detectCyrillicHomographs,
  ensureTimingConsistency
} = require('../../utils/security-enhancements')

/**
 * URL validation severity levels
 */
const SEVERITY = {
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical'
}

/**
 * Default configuration for URL validation
 */
const DEFAULT_CONFIG = {
  allowedProtocols: ['https', 'http'],
  blockedProtocols: ['file', 'ftp', 'javascript', 'data', 'vbscript'],
  allowPrivateIPs: false,
  allowLocalhost: false,
  allowLoopback: false,
  allowLinkLocal: false,
  allowedPorts: [], // Empty array means all ports allowed
  blockedPorts: [22, 23, 25, 53, 80, 135, 139, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5984, 6379, 9200, 11211, 27017],
  maxUrlLength: 2048,
  maxQueryParams: 50,
  maxQueryParamLength: 500,
  allowCredentialsInUrl: false,
  validateDNS: false, // Set to true for DNS resolution validation
  strictMode: false,
  customValidators: []
}

/**
 * Private IP ranges and special addresses
 */
const PRIVATE_IP_RANGES = {
  ipv4: [
    /^127\./, // 127.0.0.0/8 (loopback)
    /^10\./, // 10.0.0.0/8 (private)
    /^192\.168\./, // 192.168.0.0/16 (private)
    /^172\.(1[6-9]|2[0-9]|3[01])\./, // 172.16.0.0/12 (private)
    /^169\.254\./, // 169.254.0.0/16 (link-local)
    /^224\./, // 224.0.0.0/4 (multicast)
    /^255\.255\.255\.255$/ // broadcast
  ],
  ipv6: [
    /^::1$/, // loopback
    /^fe80:/i, // link-local
    /^fc00:/i, // unique local
    /^fd00:/i, // unique local
    /^ff00:/i // multicast
  ]
}

/**
 * Dangerous hostname patterns
 */
const DANGEROUS_HOSTNAMES = [
  /^localhost$/i,
  /^127\.0\.0\.1$/,
  /^::1$/,
  /\.local$/i,
  /\.internal$/i,
  /\.corp$/i,
  /\.lan$/i
]

/**
 * URL Validator Class
 */
class URLValidator {
  /**
   * Create a new URL validator
   * @param {Object} config - Validation configuration
   */
  constructor (config = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config }
  }

  /**
   * Validate a URL
   * @param {string} url - The URL to validate
   * @param {Object} options - Additional validation options
   * @returns {Promise<Object>} Validation result
   */
  async validate (url, options = {}) {
    const result = {
      isValid: false,
      sanitized: null,
      warnings: [],
      severity: null,
      metadata: {
        originalUrl: url,
        parsedUrl: null,
        protocol: null,
        hostname: null,
        port: null,
        isPrivateIP: false,
        detectedPatterns: []
      }
    }

    try {
      // Basic input validation
      if (typeof url !== 'string') {
        result.warnings.push('URL must be a string')
        result.severity = SEVERITY.HIGH
        return result
      }

      if (!url || url.trim().length === 0) {
        result.warnings.push('URL cannot be empty')
        result.severity = SEVERITY.HIGH
        return result
      }

      // Check URL length
      if (url.length > this.config.maxUrlLength) {
        result.warnings.push(`URL exceeds maximum length of ${this.config.maxUrlLength} characters`)
        result.severity = SEVERITY.MEDIUM
        return result
      }

      // Check for security patterns in raw URL
      const patternResult = detectAllPatterns(url)
      if (patternResult.detected) {
        result.metadata.detectedPatterns = patternResult.patterns
        result.warnings.push(`Security patterns detected: ${patternResult.patterns.join(', ')}`)
        result.severity = this._mapSeverity(patternResult.severity)

        if (patternResult.severity === SEVERITY_LEVELS.CRITICAL) {
          return result
        }
      }

      // Enhanced URL security checks
      const encodingResult = detectMultipleUrlEncoding(url)
      if (encodingResult.detected) {
        result.warnings.push(...encodingResult.warnings.map(w => w.message || w))
        result.metadata.multipleEncoding = encodingResult.metadata
        result.severity = this._getHigherSeverity(result.severity, 
          encodingResult.warnings.some(w => w.severity === 'HIGH') ? SEVERITY.HIGH : SEVERITY.MEDIUM)
      }

      // Check for Cyrillic homograph attacks in hostname
      const homographResult = detectCyrillicHomographs(url)
      if (homographResult.detected) {
        result.warnings.push(...homographResult.warnings.map(w => w.message || w))
        result.metadata.cyrillicHomographs = homographResult.metadata
        
        // Critical severity for domain spoofing attempts
        const hasCriticalWarnings = homographResult.warnings.some(w => w.severity === 'CRITICAL')
        if (hasCriticalWarnings) {
          result.severity = SEVERITY.CRITICAL
          return result
        } else {
          result.severity = this._getHigherSeverity(result.severity, SEVERITY.HIGH)
        }
      }

      // First, use validator.js for additional URL validation (non-blocking)
      const validatorOptions = {
        protocols: this.config.allowedProtocols.map(p => p.replace(':', '')),
        require_protocol: true,
        require_valid_protocol: true,
        disallow_auth: !this.config.allowCredentialsInUrl,
        require_host: true,
        require_port: false,
        allow_protocol_relative_urls: false,
        allow_fragments: true,
        allow_query_components: true
      }

      // Only add as metadata, don't block validation to maintain backward compatibility
      const validatorCheck = validator.isURL(url, validatorOptions)
      result.metadata.validatorCheck = validatorCheck
      if (!validatorCheck && this.config.useStrictValidation) {
        result.warnings.push('URL failed validator.js validation')
        result.severity = SEVERITY.MEDIUM
        result.metadata.failedValidatorCheck = true
      }

      // Parse URL
      let parsedUrl
      try {
        parsedUrl = new URL(url)
        result.metadata.parsedUrl = {
          protocol: parsedUrl.protocol,
          hostname: parsedUrl.hostname,
          port: parsedUrl.port,
          pathname: parsedUrl.pathname,
          search: parsedUrl.search,
          hash: parsedUrl.hash
        }
      } catch (error) {
        result.warnings.push(`Invalid URL format: ${error.message}`)
        result.severity = SEVERITY.HIGH
        return result
      }

      // Validate protocol
      const protocolResult = this._validateProtocol(parsedUrl.protocol)
      if (!protocolResult.isValid) {
        result.warnings.push(...protocolResult.warnings)
        result.severity = this._getHigherSeverity(result.severity, protocolResult.severity)
        return result
      }
      result.metadata.protocol = parsedUrl.protocol

      // Validate hostname and IP restrictions
      const hostnameResult = await this._validateHostname(parsedUrl.hostname)
      if (!hostnameResult.isValid) {
        result.warnings.push(...hostnameResult.warnings)
        result.severity = this._getHigherSeverity(result.severity, hostnameResult.severity)

        if (hostnameResult.severity === SEVERITY.CRITICAL) {
          return result
        }
      }
      result.metadata.hostname = parsedUrl.hostname
      result.metadata.isPrivateIP = hostnameResult.isPrivateIP

      // Validate port
      const portResult = this._validatePort(parsedUrl.port, parsedUrl.protocol)
      if (!portResult.isValid) {
        result.warnings.push(...portResult.warnings)
        result.severity = this._getHigherSeverity(result.severity, portResult.severity)

        if (portResult.severity === SEVERITY.CRITICAL) {
          return result
        }
      }
      result.metadata.port = parsedUrl.port || portResult.defaultPort

      // Validate credentials in URL
      if (!this.config.allowCredentialsInUrl && (parsedUrl.username || parsedUrl.password)) {
        result.warnings.push('Credentials in URL are not allowed')
        result.severity = this._getHigherSeverity(result.severity, SEVERITY.HIGH)
        return result
      }

      // Validate query parameters
      const queryResult = this._validateQueryParameters(parsedUrl.search)
      if (!queryResult.isValid) {
        result.warnings.push(...queryResult.warnings)
        result.severity = this._getHigherSeverity(result.severity, queryResult.severity)

        if (queryResult.severity === SEVERITY.CRITICAL) {
          return result
        }
      }

      // Validate path for dangerous patterns
      const pathResult = this._validatePath(parsedUrl.pathname)
      if (!pathResult.isValid) {
        result.warnings.push(...pathResult.warnings)
        result.severity = this._getHigherSeverity(result.severity, pathResult.severity)
      }

      // Run custom validators if configured
      if (this.config.customValidators.length > 0) {
        const customResult = await this._runCustomValidators(parsedUrl, options)
        if (!customResult.isValid) {
          result.warnings.push(...customResult.warnings)
          result.severity = this._getHigherSeverity(result.severity, customResult.severity)
        }
      }

      // If we get here, the URL is valid
      result.isValid = true
      result.sanitized = parsedUrl.toString()

      // Set severity to lowest if there were warnings but URL is still valid
      if (result.warnings.length === 0) {
        result.severity = null
      } else if (!result.severity) {
        result.severity = SEVERITY.LOW
      }
    } catch (error) {
      result.warnings.push(`Validation error: ${error.message}`)
      result.severity = SEVERITY.HIGH
    }

    return result
  }

  /**
   * Sanitize a URL
   * @param {string} url - The URL to sanitize
   * @param {Object} options - Sanitization options
   * @returns {Promise<Object>} Sanitization result
   */
  async sanitize (url, options = {}) {
    const validationResult = await this.validate(url, options)

    if (validationResult.isValid) {
      return validationResult
    }

    // Attempt to sanitize the URL
    let sanitized = url
    const warnings = [...validationResult.warnings]

    try {
      // Remove credentials if not allowed
      if (!this.config.allowCredentialsInUrl) {
        sanitized = sanitized.replace(/^([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)([^@/]+@)(.+)$/, '$1$3')
      }

      // Try to parse the sanitized URL
      let parsedUrl
      try {
        parsedUrl = new URL(sanitized)
      } catch (error) {
        // If still invalid, try some basic fixes
        if (!sanitized.includes('://')) {
          sanitized = 'https://' + sanitized
        }
        parsedUrl = new URL(sanitized)
      }

      // Sanitize protocol if blocked
      if (this.config.blockedProtocols.includes(parsedUrl.protocol.slice(0, -1))) {
        parsedUrl.protocol = 'https:'
        warnings.push('Changed blocked protocol to https')
      }

      // Remove dangerous query parameters
      const searchParams = new URLSearchParams(parsedUrl.search)
      let paramCount = 0
      const sanitizedParams = new URLSearchParams()

      for (const [key, value] of searchParams) {
        if (paramCount >= this.config.maxQueryParams) {
          warnings.push(`Removed excess query parameters (limit: ${this.config.maxQueryParams})`)
          break
        }

        // Sanitize parameter value
        let sanitizedValue = value
        if (sanitizedValue.length > this.config.maxQueryParamLength) {
          sanitizedValue = sanitizedValue.substring(0, this.config.maxQueryParamLength)
          warnings.push(`Truncated query parameter '${key}' to maximum length`)
        }

        // Remove dangerous characters
        sanitizedValue = sanitizedValue.replace(/[<>'"&]/g, '')

        sanitizedParams.append(key, sanitizedValue)
        paramCount++
      }

      parsedUrl.search = sanitizedParams.toString()

      // Re-validate the sanitized URL
      const revalidationResult = await this.validate(parsedUrl.toString(), options)

      return {
        isValid: revalidationResult.isValid,
        sanitized: revalidationResult.isValid ? revalidationResult.sanitized : null,
        warnings: [...warnings, ...revalidationResult.warnings],
        severity: this._getHigherSeverity(validationResult.severity, revalidationResult.severity),
        metadata: {
          ...validationResult.metadata,
          wasSanitized: true,
          sanitizationApplied: true
        }
      }
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
      }
    }
  }

  /**
   * Validate URL protocol
   * @param {string} protocol - Protocol to validate (includes colon)
   * @returns {Object} Validation result
   * @private
   */
  _validateProtocol (protocol) {
    const result = {
      isValid: true,
      warnings: [],
      severity: null
    }

    const protocolName = protocol.slice(0, -1) // Remove trailing colon

    // Check if protocol is blocked
    if (this.config.blockedProtocols.includes(protocolName)) {
      result.isValid = false
      result.warnings.push(`Protocol '${protocolName}' is blocked for security reasons`)
      result.severity = SEVERITY.CRITICAL
      return result
    }

    // Check if protocol is allowed (handle both with and without colon)
    const allowedList = this.config.allowedProtocols.map(p => p.replace(':', ''))
    if (this.config.allowedProtocols.length > 0 && !allowedList.includes(protocolName)) {
      result.isValid = false
      result.warnings.push(`Protocol '${protocolName}' is not in allowed list: ${this.config.allowedProtocols.join(', ')}`)
      result.severity = SEVERITY.HIGH
    }

    return result
  }

  /**
   * Validate hostname and IP restrictions
   * @param {string} hostname - Hostname to validate
   * @returns {Promise<Object>} Validation result
   * @private
   */
  async _validateHostname (hostname) {
    const result = {
      isValid: true,
      warnings: [],
      severity: null,
      isPrivateIP: false
    }

    if (!hostname) {
      result.isValid = false
      result.warnings.push('Hostname is missing')
      result.severity = SEVERITY.HIGH
      return result
    }

    // Check dangerous hostname patterns
    for (const pattern of DANGEROUS_HOSTNAMES) {
      if (pattern.test(hostname)) {
        const allowanceCheck = this._checkHostnameAllowance(hostname)
        if (!allowanceCheck.allowed) {
          result.isValid = false
          result.warnings.push(`Hostname '${hostname}' is ${allowanceCheck.reason}`)
          result.severity = SEVERITY.CRITICAL
          return result
        } else {
          result.warnings.push(`Warning: Accessing ${allowanceCheck.reason} hostname '${hostname}'`)
          result.severity = SEVERITY.MEDIUM
        }
      }
    }

    // Check if hostname is an IP address
    if (this._isIPAddress(hostname)) {
      const ipResult = this._validateIPAddress(hostname)
      result.isPrivateIP = ipResult.isPrivate

      if (!ipResult.isValid) {
        result.isValid = false
        result.warnings.push(...ipResult.warnings)
        result.severity = ipResult.severity
      }
    }

    // DNS validation if enabled
    if (this.config.validateDNS && result.isValid) {
      try {
        const dns = require('dns').promises
        await dns.lookup(hostname)
      } catch (error) {
        result.warnings.push(`DNS resolution failed for hostname '${hostname}'`)
        result.severity = this._getHigherSeverity(result.severity, SEVERITY.MEDIUM)
      }
    }

    return result
  }

  /**
   * Check if hostname access is allowed based on configuration
   * @param {string} hostname - Hostname to check
   * @returns {Object} Allowance check result
   * @private
   */
  _checkHostnameAllowance (hostname) {
    const lower = hostname.toLowerCase()

    if (lower === 'localhost' || lower === '127.0.0.1' || lower === '::1') {
      return {
        allowed: this.config.allowLocalhost || this.config.allowLoopback,
        reason: 'localhost/loopback'
      }
    }

    return { allowed: true, reason: null }
  }

  /**
   * Check if a string is an IP address
   * @param {string} hostname - Hostname to check
   * @returns {boolean} True if it's an IP address
   * @private
   */
  _isIPAddress (hostname) {
    // IPv4 pattern
    const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/

    // IPv6 pattern (simplified)
    const ipv6Pattern = /^([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}$/i

    return ipv4Pattern.test(hostname) || ipv6Pattern.test(hostname)
  }

  /**
   * Validate IP address for private ranges and restrictions
   * @param {string} ip - IP address to validate
   * @returns {Object} Validation result
   * @private
   */
  _validateIPAddress (ip) {
    const result = {
      isValid: true,
      warnings: [],
      severity: null,
      isPrivate: false
    }

    // Check IPv4 private ranges
    for (const pattern of PRIVATE_IP_RANGES.ipv4) {
      if (pattern.test(ip)) {
        result.isPrivate = true

        if (!this.config.allowPrivateIPs) {
          result.isValid = false
          result.warnings.push(`Access to private IP address '${ip}' is not allowed`)
          result.severity = SEVERITY.CRITICAL
          return result
        } else {
          result.warnings.push(`Warning: Accessing private IP address '${ip}'`)
          result.severity = SEVERITY.MEDIUM
        }
        break
      }
    }

    // Check IPv6 private ranges
    for (const pattern of PRIVATE_IP_RANGES.ipv6) {
      if (pattern.test(ip)) {
        result.isPrivate = true

        if (!this.config.allowPrivateIPs) {
          result.isValid = false
          result.warnings.push(`Access to private IPv6 address '${ip}' is not allowed`)
          result.severity = SEVERITY.CRITICAL
          return result
        } else {
          result.warnings.push(`Warning: Accessing private IPv6 address '${ip}'`)
          result.severity = SEVERITY.MEDIUM
        }
        break
      }
    }

    return result
  }

  /**
   * Validate port number
   * @param {string} port - Port number to validate
   * @param {string} protocol - Protocol (with colon)
   * @returns {Object} Validation result
   * @private
   */
  _validatePort (port, protocol) {
    const result = {
      isValid: true,
      warnings: [],
      severity: null,
      defaultPort: null
    }

    // Get default port for protocol
    const defaultPorts = {
      'http:': 80,
      'https:': 443,
      'ftp:': 21,
      'ssh:': 22
    }
    result.defaultPort = defaultPorts[protocol] || null

    if (!port) {
      return result // No explicit port is generally fine
    }

    const portNumber = parseInt(port, 10)

    // Validate port number range
    if (isNaN(portNumber) || portNumber < 1 || portNumber > 65535) {
      result.isValid = false
      result.warnings.push(`Invalid port number: ${port}`)
      result.severity = SEVERITY.HIGH
      return result
    }

    // Check blocked ports
    if (this.config.blockedPorts.includes(portNumber)) {
      result.isValid = false
      result.warnings.push(`Port ${portNumber} is blocked for security reasons`)
      result.severity = SEVERITY.CRITICAL
      return result
    }

    // Check allowed ports if specified
    if (this.config.allowedPorts.length > 0 && !this.config.allowedPorts.includes(portNumber)) {
      result.isValid = false
      result.warnings.push(`Port ${portNumber} is not in allowed list: ${this.config.allowedPorts.join(', ')}`)
      result.severity = SEVERITY.HIGH
    }

    return result
  }

  /**
   * Validate query parameters
   * @param {string} search - Query string (including ?)
   * @returns {Object} Validation result
   * @private
   */
  _validateQueryParameters (search) {
    const result = {
      isValid: true,
      warnings: [],
      severity: null
    }

    if (!search || search === '?') {
      return result // No query parameters
    }

    try {
      const params = new URLSearchParams(search)
      let paramCount = 0

      for (const [key, value] of params) {
        paramCount++

        // Check parameter count limit
        if (paramCount > this.config.maxQueryParams) {
          result.warnings.push(`Too many query parameters (limit: ${this.config.maxQueryParams})`)
          result.severity = this._getHigherSeverity(result.severity, SEVERITY.MEDIUM)
          break
        }

        // Check parameter value length
        if (value.length > this.config.maxQueryParamLength) {
          result.warnings.push(`Query parameter '${key}' exceeds maximum length (${this.config.maxQueryParamLength})`)
          result.severity = this._getHigherSeverity(result.severity, SEVERITY.MEDIUM)
        }

        // Check for security patterns in parameter values
        const patternResult = detectAllPatterns(value)
        if (patternResult.detected) {
          result.warnings.push(`Security patterns detected in query parameter '${key}': ${patternResult.patterns.join(', ')}`)
          result.severity = this._getHigherSeverity(result.severity, this._mapSeverity(patternResult.severity))
        }
      }
    } catch (error) {
      result.warnings.push(`Invalid query parameters: ${error.message}`)
      result.severity = SEVERITY.MEDIUM
    }

    return result
  }

  /**
   * Validate URL path
   * @param {string} pathname - URL path to validate
   * @returns {Object} Validation result
   * @private
   */
  _validatePath (pathname) {
    const result = {
      isValid: true,
      warnings: [],
      severity: null
    }

    if (!pathname || pathname === '/') {
      return result // Root path is fine
    }

    // Check for directory traversal
    if (pathname.includes('..')) {
      result.warnings.push('Directory traversal detected in URL path')
      result.severity = SEVERITY.HIGH
    }

    // Check for null bytes
    if (pathname.includes('\0')) {
      result.isValid = false
      result.warnings.push('Null byte detected in URL path')
      result.severity = SEVERITY.CRITICAL
    }

    return result
  }

  /**
   * Run custom validators
   * @param {URL} parsedUrl - Parsed URL object
   * @param {Object} options - Validation options
   * @returns {Promise<Object>} Validation result
   * @private
   */
  async _runCustomValidators (parsedUrl, options) {
    const result = {
      isValid: true,
      warnings: [],
      severity: null
    }

    for (const validator of this.config.customValidators) {
      try {
        const customResult = await validator(parsedUrl, options, this.config)
        if (!customResult.isValid) {
          result.isValid = false
          result.warnings.push(...(customResult.warnings || []))
          result.severity = this._getHigherSeverity(result.severity, customResult.severity)
        }
      } catch (error) {
        result.warnings.push(`Custom validator error: ${error.message}`)
        result.severity = this._getHigherSeverity(result.severity, SEVERITY.MEDIUM)
      }
    }

    return result
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
    }
    return mapping[patternSeverity] || SEVERITY.MEDIUM
  }

  /**
   * Get the higher severity between two severity levels
   * @param {string} current - Current severity
   * @param {string} newSeverity - New severity to compare
   * @returns {string} Higher severity
   * @private
   */
  _getHigherSeverity (current, newSeverity) {
    if (!current) return newSeverity
    if (!newSeverity) return current

    const severityOrder = [SEVERITY.LOW, SEVERITY.MEDIUM, SEVERITY.HIGH, SEVERITY.CRITICAL]
    const currentIndex = severityOrder.indexOf(current)
    const newIndex = severityOrder.indexOf(newSeverity)

    return newIndex > currentIndex ? newSeverity : current
  }

  /**
   * Update validator configuration
   * @param {Object} newConfig - New configuration to merge
   */
  updateConfig (newConfig) {
    this.config = { ...this.config, ...newConfig }
  }

  /**
   * Get current configuration
   * @returns {Object} Current configuration
   */
  getConfig () {
    return { ...this.config }
  }

  /**
   * Check if a string is a valid URL using validator.js
   * @param {string} url - URL to validate
   * @param {Object} options - Validation options
   * @returns {boolean} True if valid URL
   */
  isURL (url, options = {}) {
    const defaultOptions = {
      protocols: this.config.allowedProtocols.map(p => p.replace(':', '')),
      require_protocol: true,
      require_valid_protocol: true,
      disallow_auth: !this.config.allowCredentialsInUrl
    }
    return validator.isURL(url, { ...defaultOptions, ...options })
  }

  /**
   * Check if URL is using HTTPS
   * @param {string} url - URL to check
   * @returns {boolean} True if HTTPS
   */
  isHTTPS (url) {
    try {
      const parsed = new URL(url)
      return parsed.protocol === 'https:'
    } catch {
      return false
    }
  }

  /**
   * Check if hostname is an IP address
   * @param {string} hostname - Hostname to check
   * @returns {boolean} True if IP address
   */
  isIP (hostname) {
    return validator.isIP(hostname)
  }

  /**
   * Check if hostname is a fully qualified domain name
   * @param {string} hostname - Hostname to check
   * @returns {boolean} True if FQDN
   */
  isFQDN (hostname) {
    return validator.isFQDN(hostname, {
      require_tld: true,
      allow_underscores: false,
      allow_trailing_dot: false
    })
  }
}

/**
 * Create a URL validator with default configuration
 * @param {Object} config - Optional configuration overrides
 * @returns {URLValidator} New validator instance
 */
function createURLValidator (config = {}) {
  return new URLValidator(config)
}

/**
 * Quick validation function for simple use cases
 * @param {string} url - URL to validate
 * @param {Object} config - Optional configuration
 * @returns {Promise<Object>} Validation result
 */
async function validateURL (url, config = {}) {
  const validator = new URLValidator(config)
  return await validator.validate(url)
}

/**
 * Quick sanitization function for simple use cases
 * @param {string} url - URL to sanitize
 * @param {Object} config - Optional configuration
 * @returns {Promise<Object>} Sanitization result
 */
async function sanitizeURL (url, config = {}) {
  const validator = new URLValidator(config)
  return await validator.sanitize(url)
}

module.exports = {
  URLValidator,
  createURLValidator,
  validateURL,
  sanitizeURL,
  SEVERITY,
  DEFAULT_CONFIG,
  PRIVATE_IP_RANGES,
  DANGEROUS_HOSTNAMES
}
