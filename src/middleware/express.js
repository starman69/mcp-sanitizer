/**
 * Express.js Middleware for MCP Sanitizer
 *
 * This middleware provides comprehensive request sanitization for Express.js applications
 * serving MCP (Model Context Protocol) endpoints. It sanitizes request body, params,
 * query strings, and supports both blocking and warning modes.
 *
 * Features:
 * - Request/response sanitization with configurable modes
 * - Support for sync and async sanitization
 * - Comprehensive error handling and logging
 * - MCP-specific tool execution patterns
 * - Framework-idiomatic Express.js integration
 * - TypeScript support
 *
 * @example
 * // Basic usage
 * const express = require('express');
 * const { createExpressMiddleware } = require('mcp-sanitizer/middleware');
 *
 * const app = express();
 * app.use(express.json());
 * app.use(createExpressMiddleware({
 *   policy: 'PRODUCTION',
 *   mode: 'sanitize', // or 'block'
 *   logWarnings: true
 * }));
 *
 * @example
 * // Advanced configuration
 * app.use(createExpressMiddleware({
 *   sanitizer: customSanitizerInstance,
 *   sanitizeBody: true,
 *   sanitizeParams: true,
 *   sanitizeQuery: true,
 *   sanitizeHeaders: false,
 *   onWarning: (warnings, req) => {
 *     console.warn('Sanitization warnings:', warnings);
 *   },
 *   onBlocked: (warnings, req, res) => {
 *     res.status(400).json({ error: 'Request blocked', details: warnings });
 *   }
 * }));
 */

const MCPSanitizer = require('../index')

/**
 * Default configuration for Express middleware
 */
const DEFAULT_CONFIG = {
  // Sanitization options
  sanitizeBody: true,
  sanitizeParams: true,
  sanitizeQuery: true,
  sanitizeHeaders: false,

  // Behavioral options
  mode: 'sanitize', // 'sanitize' | 'block'
  logWarnings: true,
  addWarningsToRequest: true,

  // Response options
  blockStatusCode: 400,
  errorMessage: 'Request blocked due to security concerns',
  includeDetails: true,

  // Performance options
  async: false,
  skipHealthChecks: true,
  skipStaticFiles: true,

  // Sanitizer configuration
  policy: 'PRODUCTION',
  sanitizer: null, // Will use default if not provided

  // Callback functions
  onWarning: null,
  onBlocked: null,
  onError: null
}

/**
 * Create Express.js middleware for MCP sanitization
 * @param {Object} options - Configuration options
 * @returns {Function} Express middleware function
 */
function createExpressMiddleware (options = {}) {
  const config = { ...DEFAULT_CONFIG, ...options }

  // Initialize sanitizer if not provided
  const sanitizer = config.sanitizer || new MCPSanitizer({
    policy: config.policy,
    ...config.sanitizerOptions
  })

  // Create the middleware function
  return function mcpSanitizationMiddleware (req, res, next) {
    // Skip certain requests if configured
    if (shouldSkipRequest(req, config)) {
      return next()
    }

    // Choose sync or async processing
    if (config.async) {
      return processRequestAsync(req, res, next, sanitizer, config)
    } else {
      return processRequestSync(req, res, next, sanitizer, config)
    }
  }
}

/**
 * Check if request should be skipped based on configuration
 * @param {Object} req - Express request object
 * @param {Object} config - Middleware configuration
 * @returns {boolean} True if request should be skipped
 */
function shouldSkipRequest (req, config) {
  // Skip health check endpoints
  if (config.skipHealthChecks && isHealthCheckRequest(req)) {
    return true
  }

  // Skip static file requests
  if (config.skipStaticFiles && isStaticFileRequest(req)) {
    return true
  }

  return false
}

/**
 * Check if request is for health check endpoint
 * @param {Object} req - Express request object
 * @returns {boolean} True if health check request
 */
function isHealthCheckRequest (req) {
  const healthPaths = ['/health', '/healthcheck', '/ping', '/status']
  return healthPaths.some(path => req.path === path || req.path.startsWith(path + '/'))
}

/**
 * Check if request is for static files
 * @param {Object} req - Express request object
 * @returns {boolean} True if static file request
 */
function isStaticFileRequest (req) {
  const staticExtensions = ['.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2']
  return staticExtensions.some(ext => req.path.endsWith(ext))
}

/**
 * Process request synchronously
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 * @param {MCPSanitizer} sanitizer - Sanitizer instance
 * @param {Object} config - Middleware configuration
 */
function processRequestSync (req, res, next, sanitizer, config) {
  try {
    const sanitizationResults = {}
    let hasBlocked = false
    const allWarnings = []

    // Sanitize request body
    if (config.sanitizeBody && req.body) {
      const result = sanitizer.sanitize(req.body, {
        type: 'request_body',
        path: req.path,
        method: req.method
      })

      sanitizationResults.body = result
      if (result.blocked) hasBlocked = true
      allWarnings.push(...result.warnings)

      if (!result.blocked) {
        req.body = result.sanitized
      }
    }

    // Sanitize request parameters
    if (config.sanitizeParams && req.params) {
      const result = sanitizer.sanitize(req.params, {
        type: 'request_params',
        path: req.path,
        method: req.method
      })

      sanitizationResults.params = result
      if (result.blocked) hasBlocked = true
      allWarnings.push(...result.warnings)

      if (!result.blocked) {
        req.params = result.sanitized
      }
    }

    // Sanitize query parameters
    if (config.sanitizeQuery && req.query) {
      const result = sanitizer.sanitize(req.query, {
        type: 'request_query',
        path: req.path,
        method: req.method
      })

      sanitizationResults.query = result
      if (result.blocked) hasBlocked = true
      allWarnings.push(...result.warnings)

      if (!result.blocked) {
        req.query = result.sanitized
      }
    }

    // Sanitize headers if configured
    if (config.sanitizeHeaders && req.headers) {
      const result = sanitizer.sanitize(req.headers, {
        type: 'request_headers',
        path: req.path,
        method: req.method
      })

      sanitizationResults.headers = result
      if (result.blocked) hasBlocked = true
      allWarnings.push(...result.warnings)

      if (!result.blocked) {
        req.headers = result.sanitized
      }
    }

    // Handle blocking mode
    if (config.mode === 'block' && hasBlocked) {
      return handleBlockedRequest(req, res, allWarnings, sanitizationResults, config)
    }

    // Handle warnings
    if (allWarnings.length > 0) {
      handleWarnings(req, allWarnings, sanitizationResults, config)
    }

    // Add sanitization data to request
    if (config.addWarningsToRequest) {
      req.sanitizationWarnings = allWarnings
      req.sanitizationResults = sanitizationResults
    }

    next()
  } catch (error) {
    handleMiddlewareError(error, req, res, next, config)
  }
}

/**
 * Process request asynchronously
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 * @param {MCPSanitizer} sanitizer - Sanitizer instance
 * @param {Object} config - Middleware configuration
 */
async function processRequestAsync (req, res, next, sanitizer, config) {
  try {
    const sanitizationResults = {}
    let hasBlocked = false
    const allWarnings = []

    // Create array of sanitization tasks
    const tasks = []

    if (config.sanitizeBody && req.body) {
      tasks.push({
        type: 'body',
        data: req.body,
        context: { type: 'request_body', path: req.path, method: req.method }
      })
    }

    if (config.sanitizeParams && req.params) {
      tasks.push({
        type: 'params',
        data: req.params,
        context: { type: 'request_params', path: req.path, method: req.method }
      })
    }

    if (config.sanitizeQuery && req.query) {
      tasks.push({
        type: 'query',
        data: req.query,
        context: { type: 'request_query', path: req.path, method: req.method }
      })
    }

    if (config.sanitizeHeaders && req.headers) {
      tasks.push({
        type: 'headers',
        data: req.headers,
        context: { type: 'request_headers', path: req.path, method: req.method }
      })
    }

    // Process all sanitization tasks in parallel
    const results = await Promise.all(
      tasks.map(async (task) => {
        const result = await Promise.resolve(sanitizer.sanitize(task.data, task.context))
        return { type: task.type, result }
      })
    )

    // Process results
    for (const { type, result } of results) {
      sanitizationResults[type] = result
      if (result.blocked) hasBlocked = true
      allWarnings.push(...result.warnings)

      if (!result.blocked) {
        req[type] = result.sanitized
      }
    }

    // Handle blocking mode
    if (config.mode === 'block' && hasBlocked) {
      return handleBlockedRequest(req, res, allWarnings, sanitizationResults, config)
    }

    // Handle warnings
    if (allWarnings.length > 0) {
      handleWarnings(req, allWarnings, sanitizationResults, config)
    }

    // Add sanitization data to request
    if (config.addWarningsToRequest) {
      req.sanitizationWarnings = allWarnings
      req.sanitizationResults = sanitizationResults
    }

    next()
  } catch (error) {
    handleMiddlewareError(error, req, res, next, config)
  }
}

/**
 * Handle blocked requests
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Array} warnings - Sanitization warnings
 * @param {Object} results - Sanitization results
 * @param {Object} config - Middleware configuration
 */
function handleBlockedRequest (req, res, warnings, results, config) {
  // Log blocked request
  if (config.logWarnings) {
    // Log blocked requests (in production, use proper logger instead of console)
    if (process.env.NODE_ENV !== 'test') {
      // eslint-disable-next-line no-console
      console.warn('Blocked malicious request:', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        path: req.path,
        method: req.method,
        warnings: warnings.map(w => ({ type: w.type, message: w.message, severity: w.severity }))
      })
    }
  }

  // Call custom blocked handler if provided
  if (config.onBlocked) {
    const result = config.onBlocked(warnings, req, res, results)
    if (result === false) return // Handler took care of response
  }

  // Send default blocked response
  const response = {
    error: config.errorMessage,
    blocked: true,
    timestamp: new Date().toISOString()
  }

  if (config.includeDetails) {
    response.details = warnings.map(w => ({
      type: w.type,
      message: w.message,
      severity: w.severity,
      field: w.field
    }))
  }

  res.status(config.blockStatusCode).json(response)
}

/**
 * Handle sanitization warnings
 * @param {Object} req - Express request object
 * @param {Array} warnings - Sanitization warnings
 * @param {Object} results - Sanitization results
 * @param {Object} config - Middleware configuration
 */
function handleWarnings (req, warnings, results, config) {
  if (config.logWarnings) {
    // Log warnings (in production, use proper logger instead of console)
    if (process.env.NODE_ENV !== 'test') {
      // eslint-disable-next-line no-console
      console.warn('Request sanitization warnings:', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        path: req.path,
        method: req.method,
        warnings: warnings.map(w => ({ type: w.type, message: w.message, severity: w.severity }))
      })
    }
  }

  // Call custom warning handler if provided
  if (config.onWarning) {
    config.onWarning(warnings, req, results)
  }
}

/**
 * Handle middleware errors
 * @param {Error} error - Error object
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 * @param {Object} config - Middleware configuration
 */
function handleMiddlewareError (error, req, res, next, config) {
  // Log errors (in production, use proper logger instead of console)
  if (process.env.NODE_ENV !== 'test') {
    // eslint-disable-next-line no-console
    console.error('MCP Sanitization middleware error:', {
      error: error.message,
      stack: error.stack,
      path: req.path,
      method: req.method,
      ip: req.ip
    })
  }

  // Call custom error handler if provided
  if (config.onError) {
    const result = config.onError(error, req, res, next)
    if (result === false) return // Handler took care of response
  }

  // Send error response
  res.status(500).json({
    error: 'Internal sanitization error',
    timestamp: new Date().toISOString()
  })
}

/**
 * Create middleware specifically for MCP tool execution endpoints
 * @param {Object} options - Configuration options
 * @returns {Function} Express middleware function
 */
function createMCPToolMiddleware (options = {}) {
  const config = {
    ...DEFAULT_CONFIG,
    ...options,
    // MCP-specific defaults
    sanitizeBody: true,
    sanitizeParams: true,
    sanitizeQuery: false,
    mode: 'block', // More strict for tool execution
    toolSpecificSanitization: true
  }

  const baseMiddleware = createExpressMiddleware(config)

  return function mcpToolMiddleware (req, res, next) {
    // Add MCP-specific context
    req.mcpContext = {
      toolName: req.params.toolName || req.body?.tool_name,
      isToolExecution: true,
      timestamp: Date.now()
    }

    // Apply base middleware
    baseMiddleware(req, res, (err) => {
      if (err) return next(err)

      // Additional MCP-specific processing
      if (config.toolSpecificSanitization && req.mcpContext.toolName) {
        try {
          applyToolSpecificSanitization(req, req.mcpContext.toolName, config)
        } catch (error) {
          return handleMiddlewareError(error, req, res, next, config)
        }
      }

      next()
    })
  }
}

/**
 * Apply tool-specific sanitization rules
 * @param {Object} req - Express request object
 * @param {string} toolName - Name of the MCP tool
 * @param {Object} config - Middleware configuration
 */
function applyToolSpecificSanitization (req, toolName, config) {
  const sanitizer = config.sanitizer || new MCPSanitizer({ policy: config.policy })

  if (!req.body || !req.body.parameters) return

  const params = req.body.parameters
  let hasBlocked = false
  const toolWarnings = []

  switch (toolName) {
    case 'file_reader':
    case 'file_writer':
      if (params.file_path) {
        const result = sanitizer.sanitize(params.file_path, { type: 'file_path' })
        if (result.blocked) hasBlocked = true
        toolWarnings.push(...result.warnings)
        if (!result.blocked) params.file_path = result.sanitized
      }
      break

    case 'web_scraper':
    case 'web_fetch':
      if (params.url) {
        const result = sanitizer.sanitize(params.url, { type: 'url' })
        if (result.blocked) hasBlocked = true
        toolWarnings.push(...result.warnings)
        if (!result.blocked) params.url = result.sanitized
      }
      break

    case 'shell_executor':
    case 'command_runner':
      if (params.command) {
        const result = sanitizer.sanitize(params.command, { type: 'command' })
        if (result.blocked) hasBlocked = true
        toolWarnings.push(...result.warnings)
        if (!result.blocked) params.command = result.sanitized
      }
      break

    case 'database_query':
    case 'sql_executor':
      if (params.query) {
        const result = sanitizer.sanitize(params.query, { type: 'sql' })
        if (result.blocked) hasBlocked = true
        toolWarnings.push(...result.warnings)
        if (!result.blocked) params.query = result.sanitized
      }
      break
  }

  // Handle tool-specific blocking
  if (config.mode === 'block' && hasBlocked) {
    const error = new Error('Tool parameters blocked due to security concerns')
    error.code = 'MCP_TOOL_BLOCKED'
    error.warnings = toolWarnings
    throw error
  }

  // Add tool warnings to request
  if (toolWarnings.length > 0) {
    req.sanitizationWarnings = req.sanitizationWarnings || []
    req.sanitizationWarnings.push(...toolWarnings)
  }
}

module.exports = {
  createExpressMiddleware,
  createMCPToolMiddleware,
  DEFAULT_CONFIG
}

/**
 * Usage Examples:
 *
 * // Basic Express integration
 * const express = require('express');
 * const { createExpressMiddleware } = require('mcp-sanitizer/middleware');
 *
 * const app = express();
 * app.use(express.json());
 * app.use(createExpressMiddleware());
 *
 * // Custom configuration
 * app.use(createExpressMiddleware({
 *   mode: 'block',
 *   policy: 'STRICT',
 *   async: true,
 *   onWarning: (warnings, req) => {
 *     console.log(`Warnings for ${req.path}:`, warnings);
 *   }
 * }));
 *
 * // MCP tool-specific middleware
 * const { createMCPToolMiddleware } = require('mcp-sanitizer/middleware');
 *
 * app.use('/tools/:toolName/execute', createMCPToolMiddleware({
 *   toolSpecificSanitization: true,
 *   mode: 'block'
 * }));
 *
 * // Route-specific middleware
 * app.post('/api/mcp/execute',
 *   createExpressMiddleware({ mode: 'block' }),
 *   (req, res) => {
 *     // Handler with sanitized request
 *     console.log('Warnings:', req.sanitizationWarnings);
 *     res.json({ success: true });
 *   }
 * );
 */
