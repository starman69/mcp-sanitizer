# skipPaths Test Cases Specification

## Overview
Comprehensive test cases for the skipPaths functionality across all supported frameworks (Express, Fastify, Koa).

## Test Categories

### 1. Basic Path Matching Tests

#### Test 1.1: Exact Path Match
```javascript
it('should skip exact path matches', () => {
  const middleware = createExpressMiddleware({
    skipPaths: ['/health', '/metrics', '/ping']
  });
  
  // Test cases:
  // ✓ /health -> skipped
  // ✓ /metrics -> skipped
  // ✓ /ping -> skipped
  // ✗ /api/health -> not skipped
  // ✗ /healthcheck -> not skipped
});
```

#### Test 1.2: Path Prefix Match
```javascript
it('should skip paths with prefix match', () => {
  const middleware = createExpressMiddleware({
    skipPaths: ['/api/public', '/static']
  });
  
  // Test cases:
  // ✓ /api/public -> skipped
  // ✓ /api/public/users -> skipped
  // ✓ /api/public/data.json -> skipped
  // ✓ /static/image.png -> skipped
  // ✗ /api/private -> not skipped
});
```

#### Test 1.3: Root Path Handling
```javascript
it('should handle root path correctly', () => {
  const middleware = createExpressMiddleware({
    skipPaths: ['/']
  });
  
  // Test cases:
  // ✓ / -> skipped
  // ✗ /api -> not skipped
});
```

### 2. RegExp Pattern Tests

#### Test 2.1: Basic RegExp Patterns
```javascript
it('should support RegExp patterns', () => {
  const middleware = createExpressMiddleware({
    skipPaths: [
      /^\/static\/.*/,
      /^\/assets\/(css|js|images)\/.*/
    ]
  });
  
  // Test cases:
  // ✓ /static/file.js -> skipped
  // ✓ /assets/css/style.css -> skipped
  // ✓ /assets/js/app.js -> skipped
  // ✗ /api/static -> not skipped
});
```

#### Test 2.2: Mixed String and RegExp
```javascript
it('should support mixed string and RegExp patterns', () => {
  const middleware = createExpressMiddleware({
    skipPaths: [
      '/health',
      /^\/api\/v[0-9]+\/public/,
      '/metrics'
    ]
  });
  
  // Test cases:
  // ✓ /health -> skipped
  // ✓ /api/v1/public -> skipped
  // ✓ /api/v2/public/data -> skipped
  // ✓ /metrics -> skipped
  // ✗ /api/vnew/public -> not skipped
});
```

### 3. Edge Cases and Error Handling

#### Test 3.1: Empty and Undefined skipPaths
```javascript
it('should handle empty skipPaths array', () => {
  const middleware = createExpressMiddleware({
    skipPaths: []
  });
  // Should not skip any paths
});

it('should handle undefined skipPaths', () => {
  const middleware = createExpressMiddleware({
    // skipPaths not defined
  });
  // Should not skip any paths
});

it('should handle null skipPaths', () => {
  const middleware = createExpressMiddleware({
    skipPaths: null
  });
  // Should not skip any paths
});
```

#### Test 3.2: Invalid Path Formats
```javascript
it('should handle invalid path formats gracefully', () => {
  const middleware = createExpressMiddleware({
    skipPaths: [
      123,  // number
      {},   // object
      null, // null
      undefined // undefined
    ]
  });
  // Should ignore invalid entries and continue
});
```

#### Test 3.3: Case Sensitivity
```javascript
it('should be case sensitive by default', () => {
  const middleware = createExpressMiddleware({
    skipPaths: ['/Health']
  });
  
  // Test cases:
  // ✓ /Health -> skipped
  // ✗ /health -> not skipped
  // ✗ /HEALTH -> not skipped
});
```

### 4. Framework-Specific Tests

#### Test 4.1: Express Request Path
```javascript
it('should use request.path for Express', () => {
  const middleware = createExpressMiddleware({
    skipPaths: ['/api']
  });
  
  const req = { path: '/api/users', query: { id: 1 } };
  // Should check req.path, not full URL
});
```

#### Test 4.2: Fastify Request URL
```javascript
it('should use request.url for Fastify', async () => {
  const plugin = createFastifyPlugin({
    skipPaths: ['/api']
  });
  
  const request = { url: '/api/users?id=1' };
  // Should check request.url
});
```

#### Test 4.3: Koa Context Path
```javascript
it('should use ctx.path for Koa', async () => {
  const middleware = createKoaMiddleware({
    skipPaths: ['/api']
  });
  
  const ctx = { path: '/api/users', query: { id: 1 } };
  // Should check ctx.path
});
```

### 5. Integration Tests

#### Test 5.1: With Existing Skip Options
```javascript
it('should work alongside skipHealthChecks', () => {
  const middleware = createExpressMiddleware({
    skipPaths: ['/custom'],
    skipHealthChecks: true
  });
  
  // Test cases:
  // ✓ /custom -> skipped (via skipPaths)
  // ✓ /health -> skipped (via skipHealthChecks)
  // ✓ /ping -> skipped (via skipHealthChecks)
});

it('should work alongside skipStaticFiles', () => {
  const middleware = createExpressMiddleware({
    skipPaths: ['/api/public'],
    skipStaticFiles: true
  });
  
  // Test cases:
  // ✓ /api/public -> skipped (via skipPaths)
  // ✓ /assets/style.css -> skipped (via skipStaticFiles)
});
```

#### Test 5.2: Priority Order
```javascript
it('should check skipPaths before other skip options', () => {
  let checkOrder = [];
  
  const middleware = createExpressMiddleware({
    skipPaths: ['/health'],
    skipHealthChecks: true,
    onSkip: (reason) => checkOrder.push(reason)
  });
  
  // Request to /health should be skipped by skipPaths first
  // Verify skipPaths is checked before skipHealthChecks
});
```

### 6. Performance Tests

#### Test 6.1: Large skipPaths Array
```javascript
it('should handle large skipPaths arrays efficiently', () => {
  const paths = Array.from({ length: 1000 }, (_, i) => `/path${i}`);
  
  const middleware = createExpressMiddleware({
    skipPaths: paths
  });
  
  // Measure performance with large array
  // Should complete in reasonable time (<10ms)
});
```

#### Test 6.2: Complex RegExp Patterns
```javascript
it('should handle complex RegExp patterns efficiently', () => {
  const middleware = createExpressMiddleware({
    skipPaths: [
      /^\/api\/v[0-9]+\/(users|posts|comments)\/[0-9]+\/(edit|delete|update)$/,
      /^\/static\/(css|js|images|fonts)\/.*\.(css|js|png|jpg|woff2?)$/
    ]
  });
  
  // Test performance with complex patterns
});
```

### 7. Security Tests

#### Test 7.1: Path Traversal in skipPaths
```javascript
it('should not be vulnerable to path traversal in skipPaths', () => {
  const middleware = createExpressMiddleware({
    skipPaths: ['/../etc/passwd']
  });
  
  // Should not cause security issues
  // Path should be normalized before checking
});
```

#### Test 7.2: Malicious RegExp (ReDoS)
```javascript
it('should handle potentially malicious RegExp safely', () => {
  const middleware = createExpressMiddleware({
    skipPaths: [
      /(a+)+b/  // Potentially vulnerable to ReDoS
    ]
  });
  
  // Should handle without hanging
  // Consider adding timeout or validation
});
```

## Test Implementation Structure

```javascript
// test/middleware/skipPaths.test.js
const { describe, it, expect, beforeEach, jest } = require('@jest/globals');
const request = require('supertest');
const express = require('express');
const fastify = require('fastify');
const Koa = require('koa');

const {
  createExpressMiddleware,
  createFastifyPlugin,
  createKoaMiddleware
} = require('../../src/middleware');

describe('skipPaths Feature', () => {
  describe('Express Middleware', () => {
    let app;
    
    beforeEach(() => {
      app = express();
      app.use(express.json());
    });
    
    // Express-specific tests here
  });
  
  describe('Fastify Plugin', () => {
    let app;
    
    beforeEach(() => {
      app = fastify();
    });
    
    // Fastify-specific tests here
  });
  
  describe('Koa Middleware', () => {
    let app;
    
    beforeEach(() => {
      app = new Koa();
    });
    
    // Koa-specific tests here
  });
  
  describe('Cross-Framework Behavior', () => {
    // Tests that verify consistent behavior across frameworks
  });
});
```

## Coverage Goals

- **Line Coverage**: 100% of skipPaths-related code
- **Branch Coverage**: All conditional paths tested
- **Function Coverage**: All helper functions tested
- **Edge Cases**: All boundary conditions covered

## Performance Benchmarks

Target performance metrics:
- Path checking: <0.1ms per request
- RegExp matching: <0.5ms per request
- Large array (1000 paths): <1ms per request
- No measurable overhead when skipPaths is empty