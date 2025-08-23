# skipPaths Implementation Plan

## Problem Analysis

After reviewing the codebase, I've identified that `skipPaths` is documented in the README and API documentation but **not actually implemented** in any of the middleware files.

### Current State
1. **Documentation mentions skipPaths:**
   - README.md line 94: Shows usage example with `skipPaths: ['/health', '/metrics']`
   - API.md line 533: TypeScript definition includes `skipPaths?: string[]`

2. **No implementation found:**
   - Express middleware (`src/middleware/express.js`) does not check for skipPaths option
   - Fastify plugin (`src/middleware/fastify.js`) does not implement skipPaths
   - Koa middleware (`src/middleware/koa.js`) does not implement skipPaths
   - Main middleware index (`src/middleware/index.js`) does not handle skipPaths

3. **Current skip logic:**
   - Express middleware has `skipHealthChecks` and `skipStaticFiles` options
   - These check hardcoded paths/extensions but don't use skipPaths configuration

## Implementation Plan

### 1. Add skipPaths to Configuration

**Files to modify:**
- `src/middleware/express.js`
- `src/middleware/fastify.js`
- `src/middleware/koa.js`
- `src/middleware/index.js`

### 2. Express Middleware Implementation

```javascript
// In DEFAULT_CONFIG
skipPaths: [],  // Array of paths to skip

// Modify shouldSkipRequest function
function shouldSkipRequest (req, config) {
  // Check skipPaths first
  if (config.skipPaths && config.skipPaths.length > 0) {
    if (config.skipPaths.some(path => {
      if (typeof path === 'string') {
        return req.path === path || req.path.startsWith(path + '/')
      } else if (path instanceof RegExp) {
        return path.test(req.path)
      }
      return false
    })) {
      return true
    }
  }
  
  // Existing skip logic...
  if (config.skipHealthChecks && isHealthCheckRequest(req)) {
    return true
  }
  
  if (config.skipStaticFiles && isStaticFileRequest(req)) {
    return true
  }
  
  return false
}
```

### 3. Fastify Plugin Implementation

```javascript
// In DEFAULT_CONFIG
skipPaths: [],

// In hook registration
fastify.addHook(hookName, async (request, reply) => {
  // Check skipPaths
  if (config.skipPaths && config.skipPaths.length > 0) {
    const shouldSkip = config.skipPaths.some(path => {
      if (typeof path === 'string') {
        return request.url === path || request.url.startsWith(path + '/')
      } else if (path instanceof RegExp) {
        return path.test(request.url)
      }
      return false
    })
    
    if (shouldSkip) return
  }
  
  // Continue with sanitization...
})
```

### 4. Koa Middleware Implementation

```javascript
// In DEFAULT_CONFIG
skipPaths: [],

// In middleware function
return async function mcpSanitizationMiddleware (ctx, next) {
  // Check skipPaths
  if (config.skipPaths && config.skipPaths.length > 0) {
    const shouldSkip = config.skipPaths.some(path => {
      if (typeof path === 'string') {
        return ctx.path === path || ctx.path.startsWith(path + '/')
      } else if (path instanceof RegExp) {
        return path.test(ctx.path)
      }
      return false
    })
    
    if (shouldSkip) {
      return next()
    }
  }
  
  // Continue with sanitization...
}
```

### 5. Update Main Middleware Index

Add skipPaths to UNIFIED_CONFIG:
```javascript
const UNIFIED_CONFIG = {
  // ... existing config
  skipPaths: [],  // Array of paths to skip
  // ...
}
```

## Test Coverage Plan

### Test Cases to Add

1. **Basic path skipping:**
   - Exact path match: `/health`
   - Path prefix match: `/metrics/*`
   - Multiple paths in array

2. **RegExp support:**
   - RegExp pattern matching
   - Mixed string and RegExp patterns

3. **Framework-specific tests:**
   - Express: Test with request.path
   - Fastify: Test with request.url
   - Koa: Test with ctx.path

4. **Edge cases:**
   - Empty skipPaths array
   - null/undefined skipPaths
   - Invalid path formats
   - Case sensitivity

### Test File Structure

```javascript
describe('skipPaths functionality', () => {
  describe('Express middleware', () => {
    it('should skip exact path matches', () => {
      const middleware = createExpressMiddleware({
        skipPaths: ['/health', '/metrics']
      })
      // Test implementation
    })
    
    it('should skip path prefix matches', () => {
      const middleware = createExpressMiddleware({
        skipPaths: ['/api/public']
      })
      // Test /api/public/users should be skipped
    })
    
    it('should support RegExp patterns', () => {
      const middleware = createExpressMiddleware({
        skipPaths: [/^\/static\/.*/]
      })
      // Test RegExp matching
    })
  })
  
  // Similar test blocks for Fastify and Koa
})
```

## Implementation Priority

1. **Phase 1: Core Implementation**
   - Add skipPaths to configuration objects
   - Implement in Express middleware (most commonly used)
   - Add basic tests for Express

2. **Phase 2: Complete Coverage**
   - Implement in Fastify plugin
   - Implement in Koa middleware
   - Add comprehensive tests for all frameworks

3. **Phase 3: Enhancement**
   - Add support for glob patterns (e.g., `/api/*/public`)
   - Add performance optimizations for large skipPaths arrays
   - Add debug logging for skipped paths

## Backward Compatibility

- Default to empty array `[]` to maintain current behavior
- Keep existing `skipHealthChecks` and `skipStaticFiles` options
- Document migration path for users

## Documentation Updates

1. Update API.md with proper skipPaths documentation
2. Add examples to README.md
3. Create migration guide for existing users
4. Add JSDoc comments to implementation