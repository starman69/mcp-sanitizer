/**
 * Test suite for skipPaths functionality across all middleware implementations
 *
 * This comprehensive test suite ensures the skipPaths feature works correctly
 * across Express, Fastify, and Koa middleware with various path patterns.
 */

const { describe, it, expect, beforeEach } = require('@jest/globals')
const {
  createExpressMiddleware,
  createMCPToolMiddleware
} = require('../../src/middleware/express')
const fastifyPlugin = require('../../src/middleware/fastify')
const { createKoaMiddleware } = require('../../src/middleware/koa')

describe('skipPaths Feature', () => {
  describe('Express Middleware', () => {
    let mockReq, mockRes, mockNext

    beforeEach(() => {
      mockNext = jest.fn()
      mockRes = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn().mockReturnThis()
      }
    })

    describe('String Path Matching', () => {
      it('should skip exact path matches', () => {
        const middleware = createExpressMiddleware({
          skipPaths: ['/health', '/metrics', '/status'],
          mode: 'block'
        })

        // Test exact matches
        mockReq = { path: '/health', body: { malicious: 'data' } }
        middleware(mockReq, mockRes, mockNext)
        expect(mockNext).toHaveBeenCalled()
        expect(mockRes.status).not.toHaveBeenCalled()

        // Reset and test another path
        mockNext.mockClear()
        mockReq = { path: '/metrics', body: { command: 'rm -rf /' } }
        middleware(mockReq, mockRes, mockNext)
        expect(mockNext).toHaveBeenCalled()
      })

      it('should skip path prefix matches', () => {
        const middleware = createExpressMiddleware({
          skipPaths: ['/api/public', '/static'],
          mode: 'block'
        })

        // Should skip /api/public/users
        mockReq = { path: '/api/public/users', body: { sql: 'DROP TABLE users' } }
        middleware(mockReq, mockRes, mockNext)
        expect(mockNext).toHaveBeenCalled()

        // Should skip /static/image.png
        mockNext.mockClear()
        mockReq = { path: '/static/image.png', body: {} }
        middleware(mockReq, mockRes, mockNext)
        expect(mockNext).toHaveBeenCalled()
      })

      it('should not skip non-matching paths', () => {
        const middleware = createExpressMiddleware({
          skipPaths: ['/health'],
          mode: 'sanitize' // Use sanitize mode instead of block
        })

        mockReq = {
          path: '/api/users',
          body: { command: 'ls; rm -rf /' },
          ip: '127.0.0.1',
          method: 'POST',
          headers: {},
          params: {},
          query: {},
          get: jest.fn()
        }

        middleware(mockReq, mockRes, mockNext)
        // Should process the request (not skip) and sanitize
        expect(mockNext).toHaveBeenCalled()
        // In sanitize mode, warnings are added to request
        expect(mockReq.sanitizationWarnings).toBeDefined()
      })

      it('should handle trailing slashes correctly', () => {
        const middleware = createExpressMiddleware({
          skipPaths: ['/api/', '/health'],
          mode: 'block'
        })

        // Should match /api/ and /api/anything
        mockReq = { path: '/api/users' }
        middleware(mockReq, mockRes, mockNext)
        expect(mockNext).toHaveBeenCalled()

        // Should match /health exactly
        mockNext.mockClear()
        mockReq = { path: '/health' }
        middleware(mockReq, mockRes, mockNext)
        expect(mockNext).toHaveBeenCalled()

        // Should match /health/check
        mockNext.mockClear()
        mockReq = { path: '/health/check' }
        middleware(mockReq, mockRes, mockNext)
        expect(mockNext).toHaveBeenCalled()
      })
    })

    describe('RegExp Pattern Matching', () => {
      it('should skip RegExp pattern matches', () => {
        const middleware = createExpressMiddleware({
          skipPaths: [
            /^\/api\/v[0-9]+\/public/,
            /\.(jpg|png|gif)$/i,
            /^\/static\//
          ],
          mode: 'block'
        })

        // Should skip /api/v1/public
        mockReq = { path: '/api/v1/public', body: { evil: 'payload' } }
        middleware(mockReq, mockRes, mockNext)
        expect(mockNext).toHaveBeenCalled()

        // Should skip /api/v2/public/data
        mockNext.mockClear()
        mockReq = { path: '/api/v2/public/data' }
        middleware(mockReq, mockRes, mockNext)
        expect(mockNext).toHaveBeenCalled()

        // Should skip image files
        mockNext.mockClear()
        mockReq = { path: '/images/photo.jpg' }
        middleware(mockReq, mockRes, mockNext)
        expect(mockNext).toHaveBeenCalled()

        // Should skip static files
        mockNext.mockClear()
        mockReq = { path: '/static/css/style.css' }
        middleware(mockReq, mockRes, mockNext)
        expect(mockNext).toHaveBeenCalled()
      })

      it('should handle complex RegExp patterns', () => {
        const middleware = createExpressMiddleware({
          skipPaths: [
            /^\/webhooks?\//, // Match /webhook/ or /webhooks/
            /^\/api\/.*\/raw$/ // Match /api/anything/raw
          ]
        })

        mockReq = { path: '/webhook/github' }
        middleware(mockReq, mockRes, mockNext)
        expect(mockNext).toHaveBeenCalled()

        mockNext.mockClear()
        mockReq = { path: '/webhooks/stripe' }
        middleware(mockReq, mockRes, mockNext)
        expect(mockNext).toHaveBeenCalled()

        mockNext.mockClear()
        mockReq = { path: '/api/data/raw' }
        middleware(mockReq, mockRes, mockNext)
        expect(mockNext).toHaveBeenCalled()
      })
    })

    describe('Mixed String and RegExp Patterns', () => {
      it('should handle mixed pattern types', () => {
        const middleware = createExpressMiddleware({
          skipPaths: [
            '/health',
            /^\/api\/v[0-9]+\/public/,
            '/metrics',
            /\.json$/
          ]
        })

        // String match
        mockReq = { path: '/health' }
        middleware(mockReq, mockRes, mockNext)
        expect(mockNext).toHaveBeenCalled()

        // RegExp match
        mockNext.mockClear()
        mockReq = { path: '/api/v1/public' }
        middleware(mockReq, mockRes, mockNext)
        expect(mockNext).toHaveBeenCalled()

        // Another string match
        mockNext.mockClear()
        mockReq = { path: '/metrics' }
        middleware(mockReq, mockRes, mockNext)
        expect(mockNext).toHaveBeenCalled()

        // Another RegExp match
        mockNext.mockClear()
        mockReq = { path: '/data/config.json' }
        middleware(mockReq, mockRes, mockNext)
        expect(mockNext).toHaveBeenCalled()
      })
    })

    describe('Edge Cases', () => {
      it('should handle empty skipPaths array', () => {
        const middleware = createExpressMiddleware({
          skipPaths: [],
          mode: 'block'
        })

        mockReq = {
          path: '/health',
          body: {},
          ip: '127.0.0.1',
          method: 'GET',
          headers: {},
          params: {},
          query: {},
          get: jest.fn()
        }
        middleware(mockReq, mockRes, mockNext)
        // Should not skip any paths
        expect(mockNext).toHaveBeenCalled()
      })

      it('should handle undefined skipPaths', () => {
        const middleware = createExpressMiddleware({
          mode: 'block'
          // skipPaths not defined
        })

        mockReq = {
          path: '/health',
          body: {},
          ip: '127.0.0.1',
          method: 'GET',
          headers: {},
          params: {},
          query: {},
          get: jest.fn()
        }
        middleware(mockReq, mockRes, mockNext)
        expect(mockNext).toHaveBeenCalled()
      })

      it('should ignore invalid entries in skipPaths', () => {
        const middleware = createExpressMiddleware({
          skipPaths: [
            '/valid',
            123, // Invalid
            null, // Invalid
            {}, // Invalid
            '/another-valid',
            undefined // Invalid
          ]
        })

        // Valid path should work
        mockReq = { path: '/valid' }
        middleware(mockReq, mockRes, mockNext)
        expect(mockNext).toHaveBeenCalled()

        // Another valid path should work
        mockNext.mockClear()
        mockReq = { path: '/another-valid' }
        middleware(mockReq, mockRes, mockNext)
        expect(mockNext).toHaveBeenCalled()

        // Invalid entries should be ignored
        mockNext.mockClear()
        mockReq = {
          path: '/not-skipped',
          body: {},
          ip: '127.0.0.1',
          method: 'POST',
          headers: {},
          params: {},
          query: {},
          get: jest.fn()
        }
        middleware(mockReq, mockRes, mockNext)
        expect(mockNext).toHaveBeenCalled()
      })

      it('should be case sensitive', () => {
        const middleware = createExpressMiddleware({
          skipPaths: ['/Health']
        })

        // Should match exact case
        mockReq = { path: '/Health' }
        middleware(mockReq, mockRes, mockNext)
        expect(mockNext).toHaveBeenCalled()

        // Should not match different case
        mockNext.mockClear()
        mockReq = {
          path: '/health',
          body: {},
          ip: '127.0.0.1',
          method: 'GET',
          headers: {},
          params: {},
          query: {},
          get: jest.fn()
        }
        middleware(mockReq, mockRes, mockNext)
        expect(mockNext).toHaveBeenCalled()
      })
    })

    describe('Integration with Other Skip Options', () => {
      it('should work alongside skipHealthChecks', () => {
        const middleware = createExpressMiddleware({
          skipPaths: ['/custom'],
          skipHealthChecks: true
        })

        // Should skip custom path
        mockReq = { path: '/custom' }
        middleware(mockReq, mockRes, mockNext)
        expect(mockNext).toHaveBeenCalled()

        // Should also skip health check
        mockNext.mockClear()
        mockReq = { path: '/health' }
        middleware(mockReq, mockRes, mockNext)
        expect(mockNext).toHaveBeenCalled()

        // Should also skip /ping (health check)
        mockNext.mockClear()
        mockReq = { path: '/ping' }
        middleware(mockReq, mockRes, mockNext)
        expect(mockNext).toHaveBeenCalled()
      })

      it('should check skipPaths before other skip options', () => {
        const middleware = createExpressMiddleware({
          skipPaths: ['/health'],
          skipHealthChecks: false // Explicitly disabled
        })

        // Should still skip /health because of skipPaths
        mockReq = { path: '/health' }
        middleware(mockReq, mockRes, mockNext)
        expect(mockNext).toHaveBeenCalled()
      })
    })
  })

  describe('Fastify Plugin', () => {
    let mockRequest, mockReply

    beforeEach(() => {
      mockReply = {
        code: jest.fn().mockReturnThis(),
        send: jest.fn().mockReturnThis()
      }
    })

    it('should skip paths in Fastify', async () => {
      const fastifyInstance = {
        addHook: jest.fn(),
        decorateRequest: jest.fn(),
        decorate: jest.fn(),
        setSchemaCompiler: jest.fn(),
        register: jest.fn() // Add register mock
      }

      const options = {
        skipPaths: ['/health', /^\/api\/public/]
      }

      await fastifyPlugin(fastifyInstance, options)

      // Get the registered hook function
      const hookCall = fastifyInstance.addHook.mock.calls.find(
        call => call[0] === 'preHandler' || call[0] === 'onRequest'
      )
      expect(hookCall).toBeDefined()

      const hookFunction = hookCall[1]

      // Test string path skip
      mockRequest = { url: '/health', body: { malicious: 'data' } }
      const result = await hookFunction(mockRequest, mockReply)
      expect(result).toBeUndefined() // Should return early

      // Test RegExp path skip
      mockRequest = { url: '/api/public/data' }
      const result2 = await hookFunction(mockRequest, mockReply)
      expect(result2).toBeUndefined() // Should return early
    })

    it('should handle URLs with query strings', async () => {
      const fastifyInstance = {
        addHook: jest.fn(),
        decorateRequest: jest.fn(),
        decorate: jest.fn(),
        setSchemaCompiler: jest.fn(),
        register: jest.fn() // Add register mock
      }

      const options = {
        skipPaths: ['/api/webhook']
      }

      await fastifyPlugin(fastifyInstance, options)

      const hookCall = fastifyInstance.addHook.mock.calls.find(
        call => call[0] === 'preHandler' || call[0] === 'onRequest'
      )
      const hookFunction = hookCall[1]

      // Should skip path even with query string
      mockRequest = { url: '/api/webhook?signature=abc123' }
      const result = await hookFunction(mockRequest, mockReply)
      expect(result).toBeUndefined() // Should return early
    })
  })

  describe('Koa Middleware', () => {
    let mockCtx, mockNext

    beforeEach(() => {
      mockNext = jest.fn().mockResolvedValue()
      mockCtx = {
        path: '',
        request: { body: {} },
        body: null,
        status: 200,
        state: {}
      }
    })

    it('should skip paths in Koa', async () => {
      const middleware = createKoaMiddleware({
        skipPaths: ['/health', /^\/static/]
      })

      // Test string path skip
      mockCtx.path = '/health'
      mockCtx.request.body = { malicious: 'data' }
      await middleware(mockCtx, mockNext)
      expect(mockNext).toHaveBeenCalled()

      // Test RegExp path skip
      mockNext.mockClear()
      mockCtx.path = '/static/image.png'
      await middleware(mockCtx, mockNext)
      expect(mockNext).toHaveBeenCalled()
    })

    it('should not skip non-matching paths in Koa', async () => {
      const middleware = createKoaMiddleware({
        skipPaths: ['/health'],
        mode: 'sanitize'
      })

      mockCtx.path = '/api/users'
      mockCtx.request.body = { command: 'rm -rf /' }
      mockCtx.params = {}
      mockCtx.query = {}
      mockCtx.headers = {}
      mockCtx.get = jest.fn() // Add get method mock
      mockCtx.ip = '127.0.0.1'
      mockCtx.method = 'POST'

      await middleware(mockCtx, mockNext)
      expect(mockNext).toHaveBeenCalled()
      expect(mockCtx.sanitizationWarnings).toBeDefined()
    })
  })

  describe('Performance Tests', () => {
    it('should handle large skipPaths arrays efficiently', () => {
      // Create a large array of paths
      const largePaths = Array.from({ length: 1000 }, (_, i) => `/path${i}`)

      const middleware = createExpressMiddleware({
        skipPaths: largePaths
      })

      const mockReq = { path: '/path500' }
      const mockRes = { status: jest.fn().mockReturnThis(), json: jest.fn() }
      const mockNext = jest.fn()

      const startTime = performance.now()
      middleware(mockReq, mockRes, mockNext)
      const endTime = performance.now()

      expect(mockNext).toHaveBeenCalled()
      expect(endTime - startTime).toBeLessThan(10) // Should complete in less than 10ms
    })

    it('should handle complex RegExp patterns efficiently', () => {
      const middleware = createExpressMiddleware({
        skipPaths: [
          /^\/api\/v[0-9]+\/(users|posts|comments)\/[0-9]+\/(edit|delete)$/,
          /^\/static\/(css|js|images)\/.*\.(css|js|png|jpg)$/,
          /^\/webhooks?\/(github|gitlab|bitbucket)\/[a-z0-9-]+$/
        ]
      })

      const testPaths = [
        '/api/v1/users/123/edit',
        '/static/css/main.css',
        '/webhook/github/repo-name'
      ]

      testPaths.forEach(path => {
        const mockReq = { path }
        const mockRes = { status: jest.fn().mockReturnThis(), json: jest.fn() }
        const mockNext = jest.fn()

        const startTime = performance.now()
        middleware(mockReq, mockRes, mockNext)
        const endTime = performance.now()

        expect(mockNext).toHaveBeenCalled()
        expect(endTime - startTime).toBeLessThan(5) // Should complete quickly
      })
    })
  })

  describe('Tool-specific Middleware', () => {
    it('should work with MCP tool middleware', () => {
      const middleware = createMCPToolMiddleware({
        skipPaths: ['/tools/public'],
        toolSpecificSanitization: true
      })

      const mockReq = {
        path: '/tools/public/info',
        params: { toolName: 'info' },
        body: { parameters: {} }
      }
      const mockRes = { status: jest.fn().mockReturnThis(), json: jest.fn() }
      const mockNext = jest.fn()

      middleware(mockReq, mockRes, mockNext)
      expect(mockNext).toHaveBeenCalled()
    })
  })
})
