# skipPaths Feature Documentation

## Overview

The `skipPaths` feature allows you to configure specific paths that should bypass sanitization entirely. This is useful for health check endpoints, static file routes, public APIs, or any paths where sanitization is not needed or would cause performance overhead.

## Configuration

The `skipPaths` option accepts an array of strings and/or RegExp patterns:

```javascript
{
  skipPaths: [
    '/health',              // Exact match or prefix
    '/api/public',          // Matches /api/public and /api/public/*
    /^\/static\//,          // RegExp for /static/* paths
    /\.(jpg|png|gif)$/i     // RegExp for image files
  ]
}
```

## Usage Examples

### Express.js

```javascript
const { createExpressMiddleware } = require('mcp-sanitizer/middleware/express');

app.use(createExpressMiddleware({
  policy: 'PRODUCTION',
  skipPaths: [
    '/health',
    '/metrics',
    '/api/public',
    /^\/static\//
  ]
}));
```

### Fastify

```javascript
const mcpSanitizerPlugin = require('mcp-sanitizer/middleware/fastify');

fastify.register(mcpSanitizerPlugin, {
  policy: 'PRODUCTION',
  skipPaths: [
    '/health',
    '/api/webhook',
    /^\/public\//
  ]
});
```

### Koa

```javascript
const { createKoaMiddleware } = require('mcp-sanitizer/middleware/koa');

app.use(createKoaMiddleware({
  policy: 'PRODUCTION',
  skipPaths: [
    '/health',
    '/status',
    /^\/assets\//
  ]
}));
```

## Path Matching Behavior

### String Patterns

String patterns support both exact matching and prefix matching:

- **Exact Match**: `/health` matches only `/health`
- **Prefix Match**: `/api` matches `/api`, `/api/users`, `/api/users/123`, etc.
- **Trailing Slash**: `/api/` explicitly matches `/api/` and any subpaths

### RegExp Patterns

Regular expressions provide more flexible matching:

```javascript
skipPaths: [
  /^\/api\/v[0-9]+\/public/,   // Matches /api/v1/public, /api/v2/public, etc.
  /\.(jpg|png|gif)$/i,          // Matches any path ending with image extensions
  /^\/webhooks?\//              // Matches /webhook/ or /webhooks/
]
```

### Priority Order

Paths are checked in the following priority order:
1. `skipPaths` (highest priority)
2. `skipHealthChecks` (if enabled)
3. `skipStaticFiles` (if enabled)

## Performance Considerations

### Current Implementation

The skipPaths feature uses an `Array.some()` loop with O(n) complexity where n is the number of patterns. For most applications with reasonable numbers of skip patterns (< 100), this performs excellently.

Performance benchmarks:
- 50 paths: ~0.06ms per check
- 500 paths: ~0.94ms per check
- 1000 paths: ~3.3ms per check

### Best Practices

1. **Order patterns by frequency**: Place frequently matched patterns first
2. **Use specific patterns**: More specific patterns match faster
3. **Combine related paths**: Use prefix matching instead of multiple exact matches
4. **Consider RegExp complexity**: Simple patterns perform better than complex ones

## Security Considerations

### Important Notes

1. **Skipped paths bypass ALL sanitization**: Ensure skipped paths don't accept user input that could be malicious
2. **Public APIs**: Only skip truly public endpoints that don't process sensitive data
3. **Health checks**: Safe to skip as they typically don't process input
4. **Static files**: Generally safe to skip if served directly

### Not Recommended to Skip

- Authentication endpoints
- User data endpoints
- Database query endpoints
- File upload endpoints
- Any endpoint processing user-provided data

## Integration with Other Skip Options

The `skipPaths` feature works alongside existing skip options:

```javascript
{
  skipPaths: ['/custom'],        // Custom paths
  skipHealthChecks: true,        // Auto-skip /health, /ping, /status
  skipStaticFiles: true          // Auto-skip .js, .css, .png, etc.
}
```

## Examples

### Health Check and Metrics

```javascript
skipPaths: ['/health', '/metrics', '/ready', '/live']
```

### Public API Endpoints

```javascript
skipPaths: [
  '/api/public',
  '/api/v1/public',
  '/api/documentation'
]
```

### Static Assets

```javascript
skipPaths: [
  /^\/static\//,
  /^\/assets\//,
  /^\/public\//,
  /\.(css|js|jpg|png|gif|ico|woff2?)$/i
]
```

### Webhook Endpoints

```javascript
skipPaths: [
  '/webhooks/github',
  '/webhooks/stripe',
  /^\/webhooks?\//
]
```

### Mixed Configuration

```javascript
skipPaths: [
  // Health checks
  '/health',
  '/metrics',
  
  // Public API
  '/api/public',
  
  // Static files
  /^\/static\//,
  /\.(jpg|png|gif)$/i,
  
  // Webhooks
  /^\/webhooks?\//
]
```

## Troubleshooting

### Paths Not Being Skipped

1. **Check path format**: Ensure paths match exactly how your framework provides them
2. **Framework differences**:
   - Express: Uses `req.path` (without query string)
   - Fastify: Uses `request.url` (includes query string, but we extract path)
   - Koa: Uses `ctx.path` (without query string)
3. **Case sensitivity**: Paths are case-sensitive by default
4. **RegExp escaping**: Ensure special characters are properly escaped in RegExp

### Performance Issues

If you have many skip patterns (> 100), consider:
1. Consolidating patterns using prefix matching
2. Using broader RegExp patterns
3. Implementing custom caching if needed

## API Reference

### Configuration Option

```typescript
interface MiddlewareConfig {
  skipPaths?: Array<string | RegExp>;
  // ... other options
}
```

### Path Matching Logic

```javascript
// String matching
path === skipPath || path.startsWith(skipPath + '/')

// RegExp matching
skipPath.test(path)
```

## Migration Guide

If you were previously using only `skipHealthChecks` and `skipStaticFiles`:

**Before:**
```javascript
{
  skipHealthChecks: true,
  skipStaticFiles: true
}
```

**After (equivalent):**
```javascript
{
  skipHealthChecks: true,
  skipStaticFiles: true,
  skipPaths: []  // Add custom paths as needed
}
```

**After (explicit):**
```javascript
{
  skipPaths: [
    '/health',
    '/healthcheck',
    '/ping',
    '/status',
    /\.(js|css|png|jpg|jpeg|gif|ico|svg|woff2?)$/
  ]
}
```