/**
 * MCP Sanitizer Middleware - Main Entry Point
 *
 * This module exports middleware integrations for popular Node.js frameworks
 * including Express.js, Fastify, and Koa. Each middleware provides comprehensive
 * request sanitization for MCP (Model Context Protocol) endpoints with framework-
 * specific optimizations and patterns.
 *
 * Features:
 * - Framework-idiomatic middleware implementations
 * - Unified configuration interface across frameworks
 * - Support for both sync and async sanitization
 * - MCP-specific tool execution patterns
 * - Comprehensive error handling and logging
 * - TypeScript support
 *
 * @example
 * // Auto-detect framework and create appropriate middleware
 * const { createMiddleware } = require('mcp-sanitizer/middleware');
 * const middleware = createMiddleware('express', { policy: 'PRODUCTION' });
 *
 * @example
 * // Framework-specific imports
 * const { express, fastify, koa } = require('mcp-sanitizer/middleware');
 *
 * // Express
 * app.use(express.createExpressMiddleware({ mode: 'block' }));
 *
 * // Fastify
 * fastify.register(fastify.mcpSanitizerPlugin, { mode: 'sanitize' });
 *
 * // Koa
 * app.use(koa.createKoaMiddleware({ policy: 'STRICT' }));
 */

// const MCPSanitizer = require('../index') // Unused - commented to fix ESLint

// Import framework-specific middleware
const express = require('./express')
const fastify = require('./fastify')
const koa = require('./koa')

/**
 * Framework detection utilities
 */
const FRAMEWORK_DETECTORS = {
  express: (app) => app && typeof app.use === 'function' && typeof app.get === 'function' && app.constructor.name === 'Function',
  fastify: (app) => app && typeof app.register === 'function' && typeof app.addHook === 'function',
  koa: (app) => app && typeof app.use === 'function' && app.constructor.name === 'Application'
}

/**
 * Unified configuration interface
 */
const UNIFIED_CONFIG = {
  // Common sanitization options
  sanitizeBody: true,
  sanitizeParams: true,
  sanitizeQuery: true,
  sanitizeHeaders: false,
  sanitizeResponse: false,

  // Behavioral options
  mode: 'sanitize', // 'sanitize' | 'block'
  policy: 'PRODUCTION',
  logWarnings: true,

  // Performance options
  async: true, // Prefer async where supported
  skipHealthChecks: true,
  skipStaticFiles: true,

  // Error handling
  blockStatusCode: 400,
  errorMessage: 'Request blocked due to security concerns',
  includeDetails: true,

  // MCP-specific options
  toolSpecificSanitization: true,
  mcpContext: true,

  // Framework-specific options (will be filtered per framework)
  express: {
    addWarningsToRequest: true
  },
  fastify: {
    decorateRequest: true,
    usePreHandler: true,
    schemaCompilation: true
  },
  koa: {
    addToState: true,
    contextKey: 'sanitization'
  }
}

/**
 * Auto-detect framework and create appropriate middleware
 * @param {string|Object} framework - Framework name or app instance
 * @param {Object} options - Configuration options
 * @returns {Function|Object} Middleware function or plugin
 */
function createMiddleware (framework, options = {}) {
  const config = { ...UNIFIED_CONFIG, ...options }

  // If framework is a string, create middleware directly
  if (typeof framework === 'string') {
    return createMiddlewareByName(framework.toLowerCase(), config)
  }

  // Try to detect framework from app instance
  const detectedFramework = detectFramework(framework)
  if (detectedFramework) {
    return createMiddlewareByName(detectedFramework, config)
  }

  throw new Error('Unable to detect framework. Please specify framework name or use framework-specific imports.')
}

/**
 * Create middleware by framework name
 * @param {string} frameworkName - Name of the framework
 * @param {Object} config - Configuration options
 * @returns {Function|Object} Middleware function or plugin
 */
function createMiddlewareByName (frameworkName, config) {
  // Filter framework-specific options
  const frameworkConfig = {
    ...config,
    ...(config[frameworkName] || {})
  }

  // Remove framework-specific sections from config
  delete frameworkConfig.express
  delete frameworkConfig.fastify
  delete frameworkConfig.koa

  switch (frameworkName) {
    case 'express':
      return express.createExpressMiddleware(frameworkConfig)

    case 'fastify':
      return fastify // Return the plugin directly

    case 'koa':
      return koa.createKoaMiddleware(frameworkConfig)

    default:
      throw new Error(`Unsupported framework: ${frameworkName}`)
  }
}

/**
 * Detect framework from app instance
 * @param {Object} app - Application instance
 * @returns {string|null} Framework name or null if not detected
 */
function detectFramework (app) {
  for (const [name, detector] of Object.entries(FRAMEWORK_DETECTORS)) {
    if (detector(app)) {
      return name
    }
  }
  return null
}

/**
 * Create MCP tool-specific middleware for any framework
 * @param {string|Object} framework - Framework name or app instance
 * @param {Object} options - Configuration options
 * @returns {Function|Object} Tool-specific middleware
 */
function createMCPToolMiddleware (framework, options = {}) {
  const config = {
    ...UNIFIED_CONFIG,
    ...options,
    toolSpecificSanitization: true,
    mode: 'block' // More strict for tool execution
  }

  const frameworkName = typeof framework === 'string' ? framework.toLowerCase() : detectFramework(framework)

  switch (frameworkName) {
    case 'express':
      return express.createMCPToolMiddleware(config)

    case 'fastify':
      // Return plugin with tool-specific configuration
      return Object.assign(fastify, { defaultConfig: config })

    case 'koa':
      return koa.createMCPToolMiddleware(config)

    default:
      throw new Error(`Unsupported framework for tool middleware: ${frameworkName}`)
  }
}

/**
 * Create a universal middleware factory that works with multiple frameworks
 * @param {Object} options - Global configuration options
 * @returns {Object} Framework-specific middleware factories
 */
function createUniversalMiddleware (options = {}) {
  const config = { ...UNIFIED_CONFIG, ...options }

  return {
    express: () => express.createExpressMiddleware({ ...config, ...config.express }),
    fastify: Object.assign(fastify, { defaultConfig: { ...config, ...config.fastify } }),
    koa: () => koa.createKoaMiddleware({ ...config, ...config.koa }),

    // Auto-detection method
    auto: (app) => createMiddleware(app, config),

    // Tool-specific versions
    tool: {
      express: () => express.createMCPToolMiddleware({ ...config, ...config.express }),
      fastify: Object.assign(fastify, {
        defaultConfig: { ...config, ...config.fastify, toolSpecificSanitization: true }
      }),
      koa: () => koa.createMCPToolMiddleware({ ...config, ...config.koa })
    }
  }
}

/**
 * Create middleware with sensible defaults for different environments
 * @param {string} environment - Environment name ('development', 'production', 'testing')
 * @param {Object} customizations - Additional customizations
 * @returns {Object} Environment-specific middleware factories
 */
function createEnvironmentMiddleware (environment = 'production', customizations = {}) {
  const environmentConfigs = {
    development: {
      policy: 'DEVELOPMENT',
      mode: 'sanitize',
      logWarnings: true,
      includeDetails: true,
      async: false // Easier debugging
    },
    production: {
      policy: 'PRODUCTION',
      mode: 'block',
      logWarnings: true,
      includeDetails: false,
      async: true
    },
    testing: {
      policy: 'PERMISSIVE',
      mode: 'sanitize',
      logWarnings: false,
      includeDetails: true,
      async: false
    },
    staging: {
      policy: 'MODERATE',
      mode: 'sanitize',
      logWarnings: true,
      includeDetails: true,
      async: true
    }
  }

  const envConfig = environmentConfigs[environment.toLowerCase()] || environmentConfigs.production
  const config = { ...UNIFIED_CONFIG, ...envConfig, ...customizations }

  return createUniversalMiddleware(config)
}

/**
 * Helper function to validate middleware configuration
 * @param {Object} config - Configuration object
 * @returns {Object} Validated and normalized configuration
 */
function validateConfig (config) {
  const validated = { ...config }

  // Validate mode
  if (!['sanitize', 'block'].includes(validated.mode)) {
    // Only log in non-test environments
    if (process.env.NODE_ENV !== 'test') {
      // eslint-disable-next-line no-console
      console.warn(`Invalid mode '${validated.mode}', defaulting to 'sanitize'`)
    }
    validated.mode = 'sanitize'
  }

  // Validate policy
  const validPolicies = ['PERMISSIVE', 'DEVELOPMENT', 'MODERATE', 'PRODUCTION', 'STRICT']
  if (!validPolicies.includes(validated.policy)) {
    // Only log in non-test environments
    if (process.env.NODE_ENV !== 'test') {
      // eslint-disable-next-line no-console
      console.warn(`Invalid policy '${validated.policy}', defaulting to 'PRODUCTION'`)
    }
    validated.policy = 'PRODUCTION'
  }

  // Validate status code
  if (validated.blockStatusCode < 400 || validated.blockStatusCode >= 600) {
    // Only log in non-test environments
    if (process.env.NODE_ENV !== 'test') {
      // eslint-disable-next-line no-console
      console.warn(`Invalid blockStatusCode '${validated.blockStatusCode}', defaulting to 400`)
    }
    validated.blockStatusCode = 400
  }

  return validated
}

/**
 * Export all middleware and utilities
 */
module.exports = {
  // Main factory functions
  createMiddleware,
  createMCPToolMiddleware,
  createUniversalMiddleware,
  createEnvironmentMiddleware,

  // Framework-specific exports
  express,
  fastify,
  koa,

  // Utility functions
  detectFramework,
  validateConfig,

  // Configuration
  UNIFIED_CONFIG,
  FRAMEWORK_DETECTORS,

  // Convenience aliases
  create: createMiddleware,
  universal: createUniversalMiddleware,
  env: createEnvironmentMiddleware,

  // Backward compatibility
  middleware: {
    express: express.createExpressMiddleware,
    fastify,
    koa: koa.createKoaMiddleware
  }
}

/**
 * Type definitions for better IDE support
 * These will be used by the TypeScript definitions file
 */
module.exports.types = {
  MiddlewareConfig: 'Object',
  ExpressMiddleware: 'Function',
  FastifyPlugin: 'Function',
  KoaMiddleware: 'Function',
  Framework: 'string',
  Environment: 'string',
  SanitizationMode: 'string',
  SecurityPolicy: 'string'
}

/**
 * Usage Examples:
 *
 * // Auto-detection with Express
 * const { createMiddleware } = require('mcp-sanitizer/middleware');
 * const app = express();
 * app.use(createMiddleware('express', { policy: 'PRODUCTION' }));
 *
 * // Framework-specific usage
 * const { express, fastify, koa } = require('mcp-sanitizer/middleware');
 *
 * // Express
 * app.use(express.createExpressMiddleware({ mode: 'block' }));
 *
 * // Fastify
 * fastify.register(fastify, { policy: 'STRICT' });
 *
 * // Koa
 * app.use(koa.createKoaMiddleware({ async: true }));
 *
 * // Universal middleware factory
 * const { createUniversalMiddleware } = require('mcp-sanitizer/middleware');
 * const middleware = createUniversalMiddleware({ policy: 'PRODUCTION' });
 *
 * // Use with different frameworks
 * expressApp.use(middleware.express());
 * fastifyApp.register(middleware.fastify);
 * koaApp.use(middleware.koa());
 *
 * // Environment-specific setup
 * const { createEnvironmentMiddleware } = require('mcp-sanitizer/middleware');
 * const prodMiddleware = createEnvironmentMiddleware('production', {
 *   onBlocked: async (warnings, req, res) => {
 *     // Custom blocked handler
 *     await logSecurityEvent(warnings, req);
 *     res.status(400).json({ error: 'Request blocked' });
 *   }
 * });
 *
 * app.use(prodMiddleware.express());
 *
 * // MCP tool-specific middleware
 * const { createMCPToolMiddleware } = require('mcp-sanitizer/middleware');
 * app.use('/tools/:toolName/execute',
 *   createMCPToolMiddleware('express', {
 *     toolSpecificSanitization: true,
 *     mode: 'block'
 *   })
 * );
 */
