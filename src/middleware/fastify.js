/**
 * Fastify Plugin for MCP Sanitizer
 *
 * This plugin provides comprehensive request sanitization for Fastify applications
 * serving MCP (Model Context Protocol) endpoints. It follows Fastify's plugin
 * architecture and provides async-first sanitization with proper error handling.
 *
 * Features:
 * - Fastify-native plugin architecture with proper registration
 * - Async-first request/response sanitization
 * - Comprehensive error handling and logging
 * - MCP-specific tool execution patterns
 * - Schema validation integration
 * - Request/response hooks integration
 * - TypeScript support
 *
 * @example
 * // Basic usage
 * const fastify = require('fastify')();
 * const mcpSanitizerPlugin = require('mcp-sanitizer/middleware/fastify');
 *
 * fastify.register(mcpSanitizerPlugin, {
 *   policy: 'PRODUCTION',
 *   mode: 'sanitize',
 *   logWarnings: true
 * });
 *
 * @example
 * // Advanced configuration with custom handlers
 * fastify.register(mcpSanitizerPlugin, {
 *   sanitizer: customSanitizerInstance,
 *   sanitizeBody: true,
 *   sanitizeParams: true,
 *   sanitizeQuery: true,
 *   onWarning: async (warnings, request, reply) => {
 *     request.log.warn('Sanitization warnings:', warnings);
 *   },
 *   onBlocked: async (warnings, request, reply) => {
 *     reply.code(400).send({ error: 'Request blocked', details: warnings });
 *   }
 * });
 */

// Try to import fastify-plugin, fallback to manual plugin registration
let fp
try {
  fp = require('fastify-plugin')
} catch (error) {
  // Fallback function that mimics fastify-plugin behavior
  fp = (fn, options = {}) => {
    fn[Symbol.for('skip-override')] = true
    fn[Symbol.for('plugin-meta')] = options
    return fn
  }
}

const MCPSanitizer = require('../index')

/**
 * Default configuration for Fastify plugin
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
  skipHealthChecks: true,
  skipStaticFiles: true,
  usePreHandler: true, // Use preHandler hook vs onRequest

  // Sanitizer configuration
  policy: 'PRODUCTION',
  sanitizer: null, // Will use default if not provided

  // Callback functions
  onWarning: null,
  onBlocked: null,
  onError: null,

  // Fastify-specific options
  schemaCompilation: true,
  decorateRequest: true,
  decorateFastify: false
}

/**
 * Main plugin function
 * @param {Object} fastify - Fastify instance
 * @param {Object} options - Plugin options
 * @param {Function} done - Plugin completion callback
 */
async function mcpSanitizerPlugin (fastify, options) {
  const config = { ...DEFAULT_CONFIG, ...options }

  // Initialize sanitizer if not provided
  const sanitizer = config.sanitizer || new MCPSanitizer({
    policy: config.policy,
    ...config.sanitizerOptions
  })

  // Decorate Fastify instance if requested
  if (config.decorateFastify) {
    fastify.decorate('mcpSanitizer', sanitizer)
    fastify.decorate('mcpSanitizerConfig', config)
  }

  // Decorate request object if requested
  if (config.decorateRequest) {
    fastify.decorateRequest('sanitizationWarnings', null)
    fastify.decorateRequest('sanitizationResults', null)
    fastify.decorateRequest('mcpContext', null)
  }

  // Add schema compiler integration if enabled
  if (config.schemaCompilation) {
    addSchemaCompilerIntegration(fastify, sanitizer, config)
  }

  // Choose hook based on configuration
  const hookName = config.usePreHandler ? 'preHandler' : 'onRequest'

  fastify.addHook(hookName, async function sanitizationHook (request, reply) {
    // Skip certain requests if configured
    if (shouldSkipRequest(request, config)) {
      return
    }

    try {
      await processFastifyRequest(request, reply, sanitizer, config)
    } catch (error) {
      await handlePluginError(error, request, reply, config)
    }
  })

  // Add response sanitization hook if needed
  fastify.addHook('preSerialization', async function responsesanitizationHook (request, reply, payload) {
    if (config.sanitizeResponse && payload) {
      try {
        const result = sanitizer.sanitize(payload, {
          type: 'response_body',
          path: request.url,
          method: request.method
        })

        if (result.blocked) {
          request.log.error('Response blocked by sanitizer:', result.warnings)
          throw new Error('Response blocked due to security concerns')
        }

        if (result.warnings.length > 0) {
          request.log.warn('Response sanitization warnings:', result.warnings)
        }

        return result.sanitized
      } catch (error) {
        request.log.error('Response sanitization error:', error)
        throw error
      }
    }

    return payload
  })

  // Register MCP-specific routes and handlers
  await registerMCPRoutes(fastify, sanitizer, config)
}

/**
 * Check if request should be skipped based on configuration
 * @param {Object} request - Fastify request object
 * @param {Object} config - Plugin configuration
 * @returns {boolean} True if request should be skipped
 */
function shouldSkipRequest (request, config) {
  // Skip health check endpoints
  if (config.skipHealthChecks && isHealthCheckRequest(request)) {
    return true
  }

  // Skip static file requests
  if (config.skipStaticFiles && isStaticFileRequest(request)) {
    return true
  }

  return false
}

/**
 * Check if request is for health check endpoint
 * @param {Object} request - Fastify request object
 * @returns {boolean} True if health check request
 */
function isHealthCheckRequest (request) {
  const healthPaths = ['/health', '/healthcheck', '/ping', '/status']
  return healthPaths.some(path => request.url === path || request.url.startsWith(path + '/'))
}

/**
 * Check if request is for static files
 * @param {Object} request - Fastify request object
 * @returns {boolean} True if static file request
 */
function isStaticFileRequest (request) {
  const staticExtensions = ['.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2']
  return staticExtensions.some(ext => request.url.endsWith(ext))
}

/**
 * Process Fastify request for sanitization
 * @param {Object} request - Fastify request object
 * @param {Object} reply - Fastify reply object
 * @param {MCPSanitizer} sanitizer - Sanitizer instance
 * @param {Object} config - Plugin configuration
 */
async function processFastifyRequest (request, reply, sanitizer, config) {
  const sanitizationResults = {}
  let hasBlocked = false
  const allWarnings = []

  // Create sanitization tasks
  const tasks = []

  if (config.sanitizeBody && request.body) {
    tasks.push({
      type: 'body',
      data: request.body,
      context: { type: 'request_body', path: request.url, method: request.method }
    })
  }

  if (config.sanitizeParams && request.params) {
    tasks.push({
      type: 'params',
      data: request.params,
      context: { type: 'request_params', path: request.url, method: request.method }
    })
  }

  if (config.sanitizeQuery && request.query) {
    tasks.push({
      type: 'query',
      data: request.query,
      context: { type: 'request_query', path: request.url, method: request.method }
    })
  }

  if (config.sanitizeHeaders && request.headers) {
    tasks.push({
      type: 'headers',
      data: request.headers,
      context: { type: 'request_headers', path: request.url, method: request.method }
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
      request[type] = result.sanitized
    }
  }

  // Handle blocking mode
  if (config.mode === 'block' && hasBlocked) {
    await handleBlockedRequest(request, reply, allWarnings, sanitizationResults, config)
    return
  }

  // Handle warnings
  if (allWarnings.length > 0) {
    await handleWarnings(request, reply, allWarnings, sanitizationResults, config)
  }

  // Add sanitization data to request
  if (config.addWarningsToRequest) {
    request.sanitizationWarnings = allWarnings
    request.sanitizationResults = sanitizationResults
  }
}

/**
 * Handle blocked requests
 * @param {Object} request - Fastify request object
 * @param {Object} reply - Fastify reply object
 * @param {Array} warnings - Sanitization warnings
 * @param {Object} results - Sanitization results
 * @param {Object} config - Plugin configuration
 */
async function handleBlockedRequest (request, reply, warnings, results, config) {
  // Log blocked request
  if (config.logWarnings) {
    request.log.warn('Blocked malicious request:', {
      ip: request.ip,
      userAgent: request.headers['user-agent'],
      url: request.url,
      method: request.method,
      warnings: warnings.map(w => ({ type: w.type, message: w.message, severity: w.severity }))
    })
  }

  // Call custom blocked handler if provided
  if (config.onBlocked) {
    const result = await config.onBlocked(warnings, request, reply, results)
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

  reply.code(config.blockStatusCode).send(response)
}

/**
 * Handle sanitization warnings
 * @param {Object} request - Fastify request object
 * @param {Object} reply - Fastify reply object
 * @param {Array} warnings - Sanitization warnings
 * @param {Object} results - Sanitization results
 * @param {Object} config - Plugin configuration
 */
async function handleWarnings (request, reply, warnings, results, config) {
  if (config.logWarnings) {
    request.log.warn('Request sanitization warnings:', {
      ip: request.ip,
      userAgent: request.headers['user-agent'],
      url: request.url,
      method: request.method,
      warnings: warnings.map(w => ({ type: w.type, message: w.message, severity: w.severity }))
    })
  }

  // Call custom warning handler if provided
  if (config.onWarning) {
    await config.onWarning(warnings, request, reply, results)
  }
}

/**
 * Handle plugin errors
 * @param {Error} error - Error object
 * @param {Object} request - Fastify request object
 * @param {Object} reply - Fastify reply object
 * @param {Object} config - Plugin configuration
 */
async function handlePluginError (error, request, reply, config) {
  request.log.error('MCP Sanitization plugin error:', {
    error: error.message,
    stack: error.stack,
    url: request.url,
    method: request.method,
    ip: request.ip
  })

  // Call custom error handler if provided
  if (config.onError) {
    const result = await config.onError(error, request, reply)
    if (result === false) return // Handler took care of response
  }

  // Send error response
  reply.code(500).send({
    error: 'Internal sanitization error',
    timestamp: new Date().toISOString()
  })
}

/**
 * Add schema compiler integration for automatic validation
 * @param {Object} fastify - Fastify instance
 * @param {MCPSanitizer} sanitizer - Sanitizer instance
 * @param {Object} config - Plugin configuration
 */
function addSchemaCompilerIntegration (fastify, sanitizer, config) {
  // Store original schema compiler
  const originalCompiler = fastify.schemaCompiler

  // Replace with sanitization-aware compiler
  fastify.setSchemaCompiler(function sanitizingSchemaCompiler (schema) {
    // Get original compiled validator
    const originalValidator = originalCompiler.call(this, schema)

    // Return enhanced validator with sanitization
    return function sanitizingValidator (data) {
      // First sanitize the data
      try {
        const result = sanitizer.sanitize(data, { type: 'schema_validation' })

        if (result.blocked && config.mode === 'block') {
          return {
            error: new Error('Data blocked by sanitizer'),
            value: null
          }
        }

        // Use sanitized data for validation
        const sanitizedData = result.sanitized
        const validationResult = originalValidator(sanitizedData)

        // Add sanitization warnings to validation result
        if (result.warnings.length > 0) {
          if (validationResult.error) {
            validationResult.error.sanitizationWarnings = result.warnings
          } else {
            validationResult.sanitizationWarnings = result.warnings
          }
        }

        return validationResult
      } catch (error) {
        return {
          error: new Error('Sanitization error during validation'),
          value: null
        }
      }
    }
  })
}

/**
 * Register MCP-specific routes and handlers
 * @param {Object} fastify - Fastify instance
 * @param {MCPSanitizer} sanitizer - Sanitizer instance
 * @param {Object} config - Plugin configuration
 */
async function registerMCPRoutes (fastify, sanitizer, config) {
  // Register MCP tool execution route with enhanced sanitization
  fastify.register(async function mcpToolRoutes (fastify) {
    fastify.addHook('preHandler', async function mcpToolPreHandler (request, reply) {
      // Add MCP context
      request.mcpContext = {
        toolName: request.params.toolName || request.body?.tool_name,
        isToolExecution: true,
        timestamp: Date.now()
      }

      // Apply tool-specific sanitization
      if (request.mcpContext.toolName && request.body?.parameters) {
        try {
          await applyToolSpecificSanitization(request, request.mcpContext.toolName, sanitizer, config)
        } catch (error) {
          if (error.code === 'MCP_TOOL_BLOCKED') {
            reply.code(400).send({
              error: 'Tool parameters blocked due to security concerns',
              details: error.warnings,
              toolName: request.mcpContext.toolName
            })
            return
          }
          throw error
        }
      }
    })

    // Tool execution endpoint
    fastify.post('/tools/:toolName/execute', {
      schema: {
        params: {
          type: 'object',
          properties: {
            toolName: { type: 'string' }
          },
          required: ['toolName']
        },
        body: {
          type: 'object',
          properties: {
            parameters: { type: 'object' }
          }
        }
      }
    }, async function toolExecutionHandler (request, reply) {
      const { toolName } = request.params
      const { parameters } = request.body

      // Execute tool with sanitized parameters
      const result = {
        success: true,
        tool: toolName,
        executed_at: new Date().toISOString(),
        parameters,
        warnings: request.sanitizationWarnings || []
      }

      return result
    })
  })
}

/**
 * Apply tool-specific sanitization rules
 * @param {Object} request - Fastify request object
 * @param {string} toolName - Name of the MCP tool
 * @param {MCPSanitizer} sanitizer - Sanitizer instance
 * @param {Object} config - Plugin configuration
 */
async function applyToolSpecificSanitization (request, toolName, sanitizer, config) {
  const params = request.body.parameters
  if (!params) return

  let hasBlocked = false
  const toolWarnings = []

  const sanitizationMap = {
    file_reader: { field: 'file_path', type: 'file_path' },
    file_writer: { field: 'file_path', type: 'file_path' },
    web_scraper: { field: 'url', type: 'url' },
    web_fetch: { field: 'url', type: 'url' },
    shell_executor: { field: 'command', type: 'command' },
    command_runner: { field: 'command', type: 'command' },
    database_query: { field: 'query', type: 'sql' },
    sql_executor: { field: 'query', type: 'sql' }
  }

  const sanitizationConfig = sanitizationMap[toolName]
  if (sanitizationConfig && params[sanitizationConfig.field]) {
    const result = await Promise.resolve(
      sanitizer.sanitize(params[sanitizationConfig.field], { type: sanitizationConfig.type })
    )

    if (result.blocked) hasBlocked = true
    toolWarnings.push(...result.warnings)
    if (!result.blocked) {
      params[sanitizationConfig.field] = result.sanitized
    }
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
    request.sanitizationWarnings = request.sanitizationWarnings || []
    request.sanitizationWarnings.push(...toolWarnings)
  }
}

// Export as Fastify plugin
module.exports = fp(mcpSanitizerPlugin, {
  fastify: '4.x',
  name: 'mcp-sanitizer-plugin'
})

// Export configuration and utilities
module.exports.DEFAULT_CONFIG = DEFAULT_CONFIG
module.exports.mcpSanitizerPlugin = mcpSanitizerPlugin

/**
 * Usage Examples:
 *
 * // Basic Fastify integration
 * const fastify = require('fastify')({ logger: true });
 * const mcpSanitizerPlugin = require('mcp-sanitizer/middleware/fastify');
 *
 * fastify.register(mcpSanitizerPlugin, {
 *   policy: 'PRODUCTION',
 *   mode: 'sanitize',
 *   logWarnings: true
 * });
 *
 * // Advanced configuration with custom handlers
 * fastify.register(mcpSanitizerPlugin, {
 *   sanitizer: new MCPSanitizer({ policy: 'STRICT' }),
 *   mode: 'block',
 *   async onWarning(warnings, request, reply) {
 *     request.log.warn('Sanitization warnings:', warnings);
 *   },
 *   async onBlocked(warnings, request, reply) {
 *     reply.code(400).send({
 *       error: 'Request blocked',
 *       details: warnings.map(w => w.message)
 *     });
 *   }
 * });
 *
 * // Using decorated request properties
 * fastify.get('/api/status', async (request, reply) => {
 *   return {
 *     warnings: request.sanitizationWarnings || [],
 *     results: request.sanitizationResults || {}
 *   };
 * });
 *
 * // MCP tool execution with automatic sanitization
 * fastify.post('/tools/:toolName/execute', async (request, reply) => {
 *   const { toolName } = request.params;
 *   const { parameters } = request.body;
 *
 *   // Parameters are automatically sanitized by the plugin
 *   return {
 *     tool: toolName,
 *     parameters: parameters,
 *     warnings: request.sanitizationWarnings
 *   };
 * });
 */
