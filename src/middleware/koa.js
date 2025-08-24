/**
 * Koa Middleware for MCP Sanitizer
 *
 * This middleware provides comprehensive request sanitization for Koa applications
 * serving MCP (Model Context Protocol) endpoints. It follows Koa's async/await
 * middleware pattern and provides context-aware sanitization with proper error handling.
 *
 * Features:
 * - Native Koa async/await middleware pattern
 * - Context-aware request/response sanitization
 * - Comprehensive error handling and logging
 * - MCP-specific tool execution patterns
 * - Koa context integration
 * - Custom error and warning handlers
 * - TypeScript support
 *
 * @example
 * // Basic usage
 * const Koa = require('koa');
 * const bodyParser = require('koa-bodyparser');
 * const { createKoaMiddleware } = require('mcp-sanitizer/middleware');
 *
 * const app = new Koa();
 * app.use(bodyParser());
 * app.use(createKoaMiddleware({
 *   policy: 'PRODUCTION',
 *   mode: 'sanitize',
 *   logWarnings: true
 * }));
 *
 * @example
 * // Advanced configuration with custom handlers
 * app.use(createKoaMiddleware({
 *   sanitizer: customSanitizerInstance,
 *   sanitizeBody: true,
 *   sanitizeParams: true,
 *   sanitizeQuery: true,
 *   onWarning: async (warnings, ctx) => {
 *     ctx.logger.warn('Sanitization warnings:', warnings);
 *   },
 *   onBlocked: async (warnings, ctx) => {
 *     ctx.status = 400;
 *     ctx.body = { error: 'Request blocked', details: warnings };
 *   }
 * }));
 */

const MCPSanitizer = require('../index');
const { createOptimizedMatcher } = require('./optimized-skip-matcher');

/**
 * Default configuration for Koa middleware
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
  addWarningsToContext: true,

  // Response options
  blockStatusCode: 400,
  errorMessage: 'Request blocked due to security concerns',
  includeDetails: true,

  // Performance options
  skipHealthChecks: true,
  skipStaticFiles: true,
  skipPaths: [], // Array of paths (strings or RegExp) to skip sanitization

  // Sanitizer configuration
  policy: 'PRODUCTION',
  sanitizer: null, // Will use default if not provided

  // Callback functions
  onWarning: null,
  onBlocked: null,
  onError: null,

  // Koa-specific options
  addToState: true,
  contextKey: 'sanitization',
  loggerKey: 'logger' // Key for logger in context
};

/**
 * Create Koa middleware for MCP sanitization
 * @param {Object} options - Configuration options
 * @returns {Function} Koa middleware function
 */
function createKoaMiddleware (options = {}) {
  const config = { ...DEFAULT_CONFIG, ...options };

  // Initialize sanitizer if not provided
  const sanitizer = config.sanitizer || new MCPSanitizer({
    policy: config.policy,
    ...config.sanitizerOptions
  });

  // Pre-compile skip path matcher for optimal performance
  const skipMatcher = createOptimizedMatcher(config.skipPaths);

  // Pre-compile static checks for better performance
  const healthPaths = config.skipHealthChecks ? new Set(['/health', '/healthcheck', '/ping', '/status']) : null;
  const staticExtensions = config.skipStaticFiles ? new Set(['.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2']) : null;

  // Create backward-compatible shouldSkipRequest function
  function shouldSkipRequest (ctx, config) {
    return shouldSkipRequestOptimized(ctx, skipMatcher, healthPaths, staticExtensions);
  }

  // Return the middleware function
  return async function mcpSanitizationMiddleware (ctx, next) {
    // Skip certain requests if configured - OPTIMIZED (backward compatible)
    if (shouldSkipRequest(ctx, config)) {
      return next();
    }

    try {
      await processKoaRequest(ctx, sanitizer, config);

      // Continue to next middleware
      await next();

      // Process response if configured
      if (config.sanitizeResponse && ctx.body) {
        await processKoaResponse(ctx, sanitizer, config);
      }
    } catch (error) {
      await handleMiddlewareError(error, ctx, config);
    }
  };
}

/**
 * Check if request should be skipped based on configuration
 * OPTIMIZED VERSION: Uses pre-compiled matchers for O(1) to O(log n) performance
 * @param {Object} ctx - Koa context object
 * @param {Object} skipMatcher - Pre-compiled skip matcher
 * @param {Set|null} healthPaths - Pre-compiled health paths set
 * @param {Set|null} staticExtensions - Pre-compiled static extensions set
 * @returns {boolean} True if request should be skipped
 */
function shouldSkipRequestOptimized (ctx, skipMatcher, healthPaths, staticExtensions) {
  // Priority 1: Check skipPaths using optimized matcher - O(1) to O(log n)
  if (skipMatcher && skipMatcher.shouldSkip(ctx.path)) {
    return true;
  }

  // Priority 2: Skip health check endpoints - O(1) Set lookup
  if (healthPaths) {
    if (healthPaths.has(ctx.path)) {
      return true;
    }
    // Check for path prefixes (e.g., /health/detailed)
    for (const healthPath of healthPaths) {
      if (ctx.path.startsWith(healthPath + '/')) {
        return true;
      }
    }
  }

  // Priority 3: Skip static file requests - O(1) extension lookup
  if (staticExtensions) {
    const lastDotIndex = ctx.path.lastIndexOf('.');
    if (lastDotIndex !== -1) {
      const extension = ctx.path.substring(lastDotIndex);
      if (staticExtensions.has(extension)) {
        return true;
      }
    }
  }

  return false;
}

// Helper functions removed - functionality moved to optimized shouldSkipRequestOptimized function

/**
 * Process Koa request for sanitization
 * @param {Object} ctx - Koa context object
 * @param {MCPSanitizer} sanitizer - Sanitizer instance
 * @param {Object} config - Middleware configuration
 */
async function processKoaRequest (ctx, sanitizer, config) {
  const sanitizationResults = {};
  let hasBlocked = false;
  const allWarnings = [];

  // Create sanitization tasks
  const tasks = [];

  if (config.sanitizeBody && ctx.request.body) {
    tasks.push({
      type: 'body',
      data: ctx.request.body,
      context: { type: 'request_body', path: ctx.path, method: ctx.method }
    });
  }

  if (config.sanitizeParams && ctx.params) {
    tasks.push({
      type: 'params',
      data: ctx.params,
      context: { type: 'request_params', path: ctx.path, method: ctx.method }
    });
  }

  if (config.sanitizeQuery && ctx.query) {
    tasks.push({
      type: 'query',
      data: ctx.query,
      context: { type: 'request_query', path: ctx.path, method: ctx.method }
    });
  }

  if (config.sanitizeHeaders && ctx.headers) {
    tasks.push({
      type: 'headers',
      data: ctx.headers,
      context: { type: 'request_headers', path: ctx.path, method: ctx.method }
    });
  }

  // Process all sanitization tasks in parallel
  const results = await Promise.all(
    tasks.map(async (task) => {
      const result = await Promise.resolve(sanitizer.sanitize(task.data, task.context));
      return { type: task.type, result };
    })
  );

  // Process results
  for (const { type, result } of results) {
    sanitizationResults[type] = result;
    if (result.blocked) hasBlocked = true;
    allWarnings.push(...result.warnings);

    if (!result.blocked) {
      // Update context with sanitized data
      if (type === 'body') {
        ctx.request.body = result.sanitized;
      } else if (type === 'params') {
        ctx.params = result.sanitized;
      } else if (type === 'query') {
        ctx.query = result.sanitized;
      } else if (type === 'headers') {
        ctx.headers = result.sanitized;
      }
    }
  }

  // Handle blocking mode
  if (config.mode === 'block' && hasBlocked) {
    await handleBlockedRequest(ctx, allWarnings, sanitizationResults, config);
    return;
  }

  // Handle warnings
  if (allWarnings.length > 0) {
    await handleWarnings(ctx, allWarnings, sanitizationResults, config);
  }

  // Add sanitization data to context
  if (config.addWarningsToContext) {
    ctx.sanitizationWarnings = allWarnings;
    ctx.sanitizationResults = sanitizationResults;
  }

  // Add to state if configured
  if (config.addToState) {
    ctx.state[config.contextKey] = {
      warnings: allWarnings,
      results: sanitizationResults,
      blocked: hasBlocked,
      processed: true
    };
  }
}

/**
 * Process Koa response for sanitization
 * @param {Object} ctx - Koa context object
 * @param {MCPSanitizer} sanitizer - Sanitizer instance
 * @param {Object} config - Middleware configuration
 */
async function processKoaResponse (ctx, sanitizer, config) {
  try {
    const result = await Promise.resolve(sanitizer.sanitize(ctx.body, {
      type: 'response_body',
      path: ctx.path,
      method: ctx.method
    }));

    if (result.blocked) {
      const logger = ctx[config.loggerKey] || console;
      logger.error('Response blocked by sanitizer:', result.warnings);

      ctx.status = 500;
      ctx.body = {
        error: 'Response blocked due to security concerns',
        timestamp: new Date().toISOString()
      };
      return;
    }

    if (result.warnings.length > 0) {
      const logger = ctx[config.loggerKey] || console;
      logger.warn('Response sanitization warnings:', result.warnings);

      // Add response warnings to context
      ctx.responseWarnings = result.warnings;
      if (config.addToState) {
        ctx.state[config.contextKey] = ctx.state[config.contextKey] || {};
        ctx.state[config.contextKey].responseWarnings = result.warnings;
      }
    }

    ctx.body = result.sanitized;
  } catch (error) {
    const logger = ctx[config.loggerKey] || console;
    logger.error('Response sanitization error:', error);
    throw error;
  }
}

/**
 * Handle blocked requests
 * @param {Object} ctx - Koa context object
 * @param {Array} warnings - Sanitization warnings
 * @param {Object} results - Sanitization results
 * @param {Object} config - Middleware configuration
 */
async function handleBlockedRequest (ctx, warnings, results, config) {
  // Log blocked request
  if (config.logWarnings) {
    const logger = ctx[config.loggerKey] || console;
    logger.warn('Blocked malicious request:', {
      ip: ctx.ip,
      userAgent: ctx.get('User-Agent'),
      path: ctx.path,
      method: ctx.method,
      warnings: warnings.map(w => ({ type: w.type, message: w.message, severity: w.severity }))
    });
  }

  // Call custom blocked handler if provided
  if (config.onBlocked) {
    const result = await config.onBlocked(warnings, ctx, results);
    if (result === false) return; // Handler took care of response
  }

  // Send default blocked response
  const response = {
    error: config.errorMessage,
    blocked: true,
    timestamp: new Date().toISOString()
  };

  if (config.includeDetails) {
    response.details = warnings.map(w => ({
      type: w.type,
      message: w.message,
      severity: w.severity,
      field: w.field
    }));
  }

  ctx.status = config.blockStatusCode;
  ctx.body = response;
}

/**
 * Handle sanitization warnings
 * @param {Object} ctx - Koa context object
 * @param {Array} warnings - Sanitization warnings
 * @param {Object} results - Sanitization results
 * @param {Object} config - Middleware configuration
 */
async function handleWarnings (ctx, warnings, results, config) {
  if (config.logWarnings) {
    const logger = ctx[config.loggerKey] || console;
    logger.warn('Request sanitization warnings:', {
      ip: ctx.ip,
      userAgent: ctx.get('User-Agent'),
      path: ctx.path,
      method: ctx.method,
      warnings: warnings.map(w => ({ type: w.type, message: w.message, severity: w.severity }))
    });
  }

  // Call custom warning handler if provided
  if (config.onWarning) {
    await config.onWarning(warnings, ctx, results);
  }
}

/**
 * Handle middleware errors
 * @param {Error} error - Error object
 * @param {Object} ctx - Koa context object
 * @param {Object} config - Middleware configuration
 */
async function handleMiddlewareError (error, ctx, config) {
  const logger = ctx[config.loggerKey] || console;
  logger.error('MCP Sanitization middleware error:', {
    error: error.message,
    stack: error.stack,
    path: ctx.path,
    method: ctx.method,
    ip: ctx.ip
  });

  // Call custom error handler if provided
  if (config.onError) {
    const result = await config.onError(error, ctx);
    if (result === false) return; // Handler took care of response
  }

  // Send error response
  ctx.status = 500;
  ctx.body = {
    error: 'Internal sanitization error',
    timestamp: new Date().toISOString()
  };
}

/**
 * Create middleware specifically for MCP tool execution endpoints
 * @param {Object} options - Configuration options
 * @returns {Function} Koa middleware function
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
  };

  const baseMiddleware = createKoaMiddleware(config);

  return async function mcpToolMiddleware (ctx, next) {
    // Add MCP-specific context
    ctx.mcpContext = {
      toolName: ctx.params.toolName || ctx.request.body?.tool_name,
      isToolExecution: true,
      timestamp: Date.now()
    };

    // Apply base middleware
    await baseMiddleware(ctx, async () => {
      // Additional MCP-specific processing
      if (config.toolSpecificSanitization && ctx.mcpContext.toolName) {
        try {
          await applyToolSpecificSanitization(ctx, ctx.mcpContext.toolName, config);
        } catch (error) {
          if (error.code === 'MCP_TOOL_BLOCKED') {
            ctx.status = 400;
            ctx.body = {
              error: 'Tool parameters blocked due to security concerns',
              details: error.warnings,
              toolName: ctx.mcpContext.toolName
            };
            return;
          }
          throw error;
        }
      }

      await next();
    });
  };
}

/**
 * Apply tool-specific sanitization rules
 * @param {Object} ctx - Koa context object
 * @param {string} toolName - Name of the MCP tool
 * @param {Object} config - Middleware configuration
 */
async function applyToolSpecificSanitization (ctx, toolName, config) {
  const sanitizer = config.sanitizer || new MCPSanitizer({ policy: config.policy });

  if (!ctx.request.body || !ctx.request.body.parameters) return;

  const params = ctx.request.body.parameters;
  let hasBlocked = false;
  const toolWarnings = [];

  const sanitizationMap = {
    file_reader: { field: 'file_path', type: 'file_path' },
    file_writer: { field: 'file_path', type: 'file_path' },
    web_scraper: { field: 'url', type: 'url' },
    web_fetch: { field: 'url', type: 'url' },
    shell_executor: { field: 'command', type: 'command' },
    command_runner: { field: 'command', type: 'command' },
    database_query: { field: 'query', type: 'sql' },
    sql_executor: { field: 'query', type: 'sql' }
  };

  const sanitizationConfig = sanitizationMap[toolName];
  if (sanitizationConfig && params[sanitizationConfig.field]) {
    const result = await Promise.resolve(
      sanitizer.sanitize(params[sanitizationConfig.field], { type: sanitizationConfig.type })
    );

    if (result.blocked) hasBlocked = true;
    toolWarnings.push(...result.warnings);
    if (!result.blocked) {
      params[sanitizationConfig.field] = result.sanitized;
    }
  }

  // Handle tool-specific blocking
  if (config.mode === 'block' && hasBlocked) {
    const error = new Error('Tool parameters blocked due to security concerns');
    error.code = 'MCP_TOOL_BLOCKED';
    error.warnings = toolWarnings;
    throw error;
  }

  // Add tool warnings to context
  if (toolWarnings.length > 0) {
    ctx.sanitizationWarnings = ctx.sanitizationWarnings || [];
    ctx.sanitizationWarnings.push(...toolWarnings);
  }
}

/**
 * Create a composed middleware for complete MCP server setup
 * @param {Object} options - Configuration options
 * @returns {Function} Composed Koa middleware function
 */
function createMCPServerMiddleware (options = {}) {
  const config = { ...DEFAULT_CONFIG, ...options };
  const baseMiddleware = createKoaMiddleware(config);
  const toolMiddleware = createMCPToolMiddleware(config);

  return async function mcpServerMiddleware (ctx, next) {
    // Check if this is a tool execution request
    const isToolRequest = ctx.path.includes('/tools/') && ctx.path.includes('/execute');

    if (isToolRequest) {
      await toolMiddleware(ctx, next);
    } else {
      await baseMiddleware(ctx, next);
    }
  };
}

module.exports = {
  createKoaMiddleware,
  createMCPToolMiddleware,
  createMCPServerMiddleware,
  DEFAULT_CONFIG
};

/**
 * Usage Examples:
 *
 * // Basic Koa integration
 * const Koa = require('koa');
 * const bodyParser = require('koa-bodyparser');
 * const { createKoaMiddleware } = require('mcp-sanitizer/middleware');
 *
 * const app = new Koa();
 * app.use(bodyParser());
 * app.use(createKoaMiddleware({
 *   policy: 'PRODUCTION',
 *   mode: 'sanitize',
 *   logWarnings: true
 * }));
 *
 * // Custom configuration with async handlers
 * app.use(createKoaMiddleware({
 *   sanitizer: new MCPSanitizer({ policy: 'STRICT' }),
 *   mode: 'block',
 *   async onWarning(warnings, ctx) {
 *     ctx.logger.warn('Sanitization warnings:', warnings);
 *     // Store warnings in database
 *     await ctx.db.warnings.create({ warnings, ip: ctx.ip });
 *   },
 *   async onBlocked(warnings, ctx) {
 *     ctx.status = 400;
 *     ctx.body = {
 *       error: 'Request blocked',
 *       details: warnings.map(w => w.message),
 *       requestId: ctx.state.requestId
 *     };
 *   }
 * }));
 *
 * // MCP tool-specific middleware
 * const Router = require('@koa/router');
 * const router = new Router();
 *
 * router.post('/tools/:toolName/execute',
 *   createMCPToolMiddleware({ mode: 'block' }),
 *   async (ctx) => {
 *     const { toolName } = ctx.params;
 *     const { parameters } = ctx.request.body;
 *
 *     // Parameters are automatically sanitized
 *     ctx.body = {
 *       tool: toolName,
 *       parameters: parameters,
 *       warnings: ctx.sanitizationWarnings || [],
 *       executed_at: new Date().toISOString()
 *     };
 *   }
 * );
 *
 * // Complete MCP server setup
 * app.use(createMCPServerMiddleware({
 *   policy: 'PRODUCTION',
 *   logWarnings: true,
 *   addToState: true,
 *   contextKey: 'mcp'
 * }));
 *
 * // Access sanitization data in routes
 * app.use(async (ctx, next) => {
 *   console.log('Sanitization state:', ctx.state.mcp);
 *   console.log('Warnings:', ctx.sanitizationWarnings);
 *   await next();
 * });
 */
