# MCP Sanitizer

A comprehensive security sanitization library for Model Context Protocol (MCP) servers, designed to prevent common attack vectors including command injection, SQL injection, directory traversal, prototype pollution, and code execution attempts.

[![npm version](https://badge.fury.io/js/mcp-sanitizer.svg)](https://badge.fury.io/js/mcp-sanitizer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security Tests](https://img.shields.io/badge/Security%20Tests-600%2B-brightgreen)](./test)

## 🔒 Security Features

MCP Sanitizer provides comprehensive, defense-in-depth protection:

- ✅ **Multi-layered Protection**: Command injection, SQL injection, XSS, NoSQL injection, path traversal
- ✅ **Advanced Unicode Defense**: Homograph detection, multi-pass normalization, zero-width removal
- ✅ **Context-aware Validation**: Specialized rules for file paths, URLs, commands, and SQL queries
- ✅ **Database-specific SQL Protection**: PostgreSQL, MySQL, MSSQL, Oracle validation and escaping
- ✅ **Framework Integration**: Express, Fastify, and Koa middleware with `skipPaths` support
- ✅ **Security Policies**: Pre-configured policies (STRICT, MODERATE, PERMISSIVE, DEVELOPMENT, PRODUCTION)
- ✅ **Comprehensive Validation**: Checking 42+ attack vectors across 12 validation layers in <1ms
- ✅ **Comprehensive Testing**: 670 tests with 78% coverage, zero false negatives, sub-millisecond performance

### Security Philosophy
While we maintain rigorous security standards and comprehensive test coverage, we acknowledge that:
- No security solution is 100% bulletproof against unknown threats
- Zero-day vulnerabilities may emerge in the future
- Defense-in-depth is essential (use multiple security layers)
- Regular updates are crucial for evolving threat landscape

We encourage responsible disclosure of any security issues via GitHub Security Advisories.

## Installation

```bash
npm install mcp-sanitizer
```

## Quick Start

```javascript
const MCPSanitizer = require('mcp-sanitizer');

// Use default configuration
const sanitizer = new MCPSanitizer();

// Or use a security policy
const strictSanitizer = new MCPSanitizer('STRICT');

// Sanitize MCP tool call
const toolCall = {
  name: "file_reader",
  parameters: {
    file_path: "../../../etc/passwd"  // Malicious input
  }
};

const result = sanitizer.sanitize(toolCall);
if (result.blocked) {
  console.log('Attack blocked:', result.warnings);
} else {
  console.log('Safe input:', result.sanitized);
}
```

## Security Policies

The MCP Sanitizer includes five pre-configured security policies:

| Policy | Use Case | String Limit | Protocols | Blocking Level |
|--------|----------|--------------|-----------|----------------|
| **STRICT** | High-security, untrusted input | 1,000 chars | HTTPS only | Medium+ |
| **MODERATE** | Balanced production security | 5,000 chars | HTTP, HTTPS, MCP | High+ |
| **PERMISSIVE** | Trusted environments | 50,000 chars | HTTP, HTTPS, FTP, MCP, File | Critical only |
| **DEVELOPMENT** | Development with debugging | 20,000 chars | HTTP, HTTPS, MCP, File | High+ |
| **PRODUCTION** | Production environments | 8,000 chars | HTTPS, MCP | High+ |

```javascript
// Use a security policy
const sanitizer = new MCPSanitizer('PRODUCTION');

// Use policy with customizations
const customSanitizer = new MCPSanitizer({
  policy: 'MODERATE',
  maxStringLength: 15000,
  allowedProtocols: ['https', 'mcp'],
  blockSeverity: 'MEDIUM'  // Block medium severity and above
});
```
## Framework Middleware

### Express.js

```javascript
const express = require('express');
const { createMCPMiddleware } = require('mcp-sanitizer');

const app = express();
app.use(express.json());

// Auto-detect framework and apply middleware
app.use(createMCPMiddleware());

// Or specify configuration
app.use(createMCPMiddleware({
  policy: 'PRODUCTION',
  mode: 'sanitize', // or 'block'
  skipPaths: ['/health', '/metrics']  // Skip sanitization for these paths
}));

app.post('/tools/:toolName/execute', (req, res) => {
  // req.body is now sanitized
  // req.sanitizationWarnings contains any warnings
});
```

### Fastify

```javascript
const fastify = require('fastify')();
const { createFastifyPlugin } = require('mcp-sanitizer');

// Register as plugin
fastify.register(createFastifyPlugin({
  policy: 'MODERATE'
}));
```

### Koa

```javascript
const Koa = require('koa');
const { createKoaMiddleware } = require('mcp-sanitizer');

const app = new Koa();
app.use(createKoaMiddleware({
  policy: 'STRICT'
}));
```

## Configuration Options

### Using Configuration Builder (Fluent API)

```javascript
const { createConfigBuilder } = require('mcp-sanitizer');

const config = createConfigBuilder()
  .usePolicy('MODERATE')
  .maxStringLength(20000)
  .allowProtocols(['https', 'mcp'])
  .allowFileExtensions(['.txt', '.json', '.md', '.csv'])
  .blockOnSeverity('high')
  .strictMode(true)
  .patternDetection({
    enableCommandInjection: true,
    enableSQLInjection: true,
    enablePrototypePollution: true,
    enableTemplateInjection: false
  })
  .build();

const sanitizer = new MCPSanitizer(config);
```

### Direct Configuration

```javascript
const sanitizer = new MCPSanitizer({
  // Limits
  maxStringLength: 10000,
  maxDepth: 10,
  maxArrayLength: 1000,
  maxObjectKeys: 100,
  
  // Security
  allowedProtocols: ['https', 'mcp'],
  allowedFileExtensions: ['.txt', '.json', '.md'],
  blockOnSeverity: 'high',
  strictMode: false,
  
  // Patterns
  blockedPatterns: [
    /\$\{.*?\}/g,     // Template injection
    /__proto__/gi,    // Prototype pollution
    /require\s*\(/gi  // Code execution
  ],
  
  // Context-specific settings
  contextSettings: {
    url: {
      allowPrivateIPs: false,
      allowLocalhostWithoutPort: false
    },
    filePath: {
      allowAbsolutePaths: false,
      allowedDirectories: ['./data']
    }
  }
});
```

## Supported Attack Vectors

- **Directory Traversal** - Relative path escapes, absolute system paths, UNC paths
- **Command Injection** - Shell metacharacters, chained commands, pipe redirection
- **SQL Injection** - Union-based, boolean-based, time-based, stacked queries, comment injection
- **Prototype Pollution** - Proto/constructor manipulation, deep property injection
- **Template Injection** - Server-side template engines, JNDI lookups, expression languages
- **Code Execution** - Dynamic evaluation, module loading, function constructors

## API Reference

### `new MCPSanitizer(options?)`

Create a new sanitizer instance.

**Parameters:**
- `options`: Configuration object, security policy name, or policy with customizations

### `sanitizer.sanitize(input, context?)`

Sanitizes input data and returns a result object.

**Parameters:**
- `input`: The data to sanitize (any type)
- `context`: Optional context object with `type` field

**Returns:**
```javascript
{
  sanitized: any,     // Sanitized data (null if blocked)
  warnings: string[], // Array of warning messages
  blocked: boolean    // True if input was blocked
}
```

**Context Types:**
- `file_path`: Apply file path validation
- `url`: Apply URL validation  
- `command`: Apply command validation
- `sql`: Apply SQL query validation

### Specialized Methods

```javascript
// Sanitize specific input types
sanitizer.sanitizeFilePath('/path/to/file');
sanitizer.sanitizeURL('https://example.com');
sanitizer.sanitizeCommand('ls -la');
sanitizer.sanitizeSQL('SELECT * FROM users WHERE id = ?');
```

### Configuration Methods

```javascript
// Get configuration summary
const summary = sanitizer.getConfigSummary();

// Update configuration at runtime
sanitizer.updateConfig({
  maxStringLength: 25000
});

// Apply new security policy
sanitizer.applyPolicy('STRICT', {
  maxStringLength: 5000 // Override
});

// Check environment compatibility
const compatibility = sanitizer.checkEnvironmentCompatibility('production');
```

## Security Libraries Used

The MCP Sanitizer leverages trusted, industry-standard security libraries:

- **[escape-html](https://github.com/component/escape-html)** - HTML entity encoding (3-4x faster than regex)
- **[sqlstring](https://github.com/mysqljs/sqlstring)** - MySQL-compatible SQL escaping
- **[shell-quote](https://github.com/substack/node-shell-quote)** - Shell command escaping
- **[validator](https://github.com/validatorjs/validator.js)** - String validation and sanitization
- **[sanitize-filename](https://github.com/parshap/node-sanitize-filename)** - Filename sanitization
- **[path-is-inside](https://github.com/domenic/path-is-inside)** - Path containment checking
- **[unorm](https://github.com/walling/unorm)** - Unicode normalization (NFC, NFD, NFKC, NFKD)

## Testing

```bash
# Run tests
npm test

# Run with coverage
npm run test:coverage

# Watch mode
npm run test:watch

# Security audit
npm run security-audit
```

## Performance

- **Sub-millisecond Validation**: <1ms average latency for complete validation (12 layers checking 40+ attack vectors)
- **High Throughput**: 7,500+ operations/second average, scales linearly with CPU cores
- **Industry-Leading Libraries**: escape-html (31M ops/sec), sqlstring (44M ops/sec), shell-quote (2.5M ops/sec)
- **Production Ready**: Sub-millisecond response times enable real-time validation without user-perceivable delays
- **Memory Efficient**: Configurable limits prevent exhaustion (<100MB under attack, typical usage <60MB)
- **Zero Overhead**: No artificial delays, pure validation logic only
- **Scalable**: Stateless design allows horizontal scaling across multiple cores/instances

### Performance Metrics

| Metric | Value | Details |
|--------|-------|---------|
| **Average Latency** | <1ms | 0.447ms - 0.84ms depending on input complexity |
| **Throughput** | 7,500+ ops/sec | Per CPU core, scales linearly |
| **Attack Detection** | 0.28ms - 2.39ms | All 42 attack vectors blocked |
| **Memory Usage** | <60MB typical | <100MB maximum under stress |
| **CPU Efficiency** | Optimized | No busy-wait loops, pure validation |

**Validation Layers**: Command injection, SQL injection (4 databases), NoSQL injection, XSS, path traversal, prototype pollution, template injection, Unicode normalization (4 passes), multi-layer encoding detection, file extension validation, protocol validation

**Optimization Options**: Use `skipPaths` middleware to exempt low-risk routes (health checks, static assets, metrics endpoints)

## Examples

### Environment-based Configuration

```javascript
const { createRecommendedConfig } = require('mcp-sanitizer');

// Get recommended configuration for your environment
const { config, metadata } = createRecommendedConfig('production', 'low');
console.log(metadata.rationale); // Why this policy was recommended

const sanitizer = new MCPSanitizer(config);
```

### Custom Security Patterns

```javascript
const sanitizer = new MCPSanitizer({
  blockedPatterns: [
    // Default patterns plus custom ones
    /bitcoin|cryptocurrency/i,  // Block crypto content
    /\b\d{16}\b/,              // Block credit card numbers
    /password|secret|token/i    // Block sensitive keywords
  ],
  sqlKeywords: [
    // Add custom SQL keywords
    'MERGE', 'UPSERT', 'BULK'
  ]
});
```

### MCP Tool Parameter Validation

```javascript
// Before executing file operations
const pathResult = sanitizer.sanitize(params.file_path, { type: 'file_path' });
if (pathResult.blocked) {
  throw new Error('Invalid file path');
}

// Before making HTTP requests
const urlResult = sanitizer.sanitize(params.url, { type: 'url' });
if (urlResult.blocked) {
  throw new Error('Invalid or restricted URL');
}
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Write tests for new functionality
4. Ensure all tests pass (`npm test`)
5. Lint your code (`npm run lint`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## Security

### 🛡️ Run Security Benchmarks

Run comprehensive security benchmarks to validate protection:

```bash
# Quick demo (10 attack vectors + performance test)
node benchmark/quick-demo.js

# Comprehensive security benchmark (42 attack vectors)
node benchmark/advanced-security-benchmark.js

# Performance benchmarks
node benchmark/library-performance.js
node benchmark/skip-paths-performance.js
```

**Expected Results:**
- All 42 attack vectors blocked (100%)
- Average latency: <1ms
- Throughput: 7,500+ ops/sec
- Memory usage: <60MB

### 🔒 Security Testing Coverage

| Category | Test Cases | Coverage |
|----------|------------|----------|
| **XSS Vectors** | 13 | DOM-based, attribute injection, polyglots |
| **SQL Injection** | 10 | All major databases, blind/time-based |
| **Command Injection** | 10 | Shell commands, environment vars, process substitution |
| **Path Traversal** | 9 | Directory traversal, absolute paths, UNC |
| **ReDoS Protection** | 22 | Polynomial backtracking, timeout guards |
| **Prototype Pollution** | 3 | `__proto__`, constructor, prototype |
| **Memory Safety** | 3 | Bounded memory usage under attack |

### 🎯 Security Best Practices

1. ✅ **Use STRICT or PRODUCTION policy** for untrusted input
2. ✅ **Update regularly** for latest security patches
3. ✅ **Monitor blocked attempts** in production for security insights
4. ✅ **Implement defense-in-depth** - multiple security layers
5. ✅ **Test with your attack vectors** using provided benchmarks
6. ✅ **Use crypto.timingSafeEqual()** for secret comparison
7. ✅ **Enable rate limiting** at infrastructure layer

### 📝 Security Resources

- [Security Documentation](./docs/SECURITY.md) - Comprehensive security information
- [Benchmark Documentation](./benchmark/README.md) - Performance and security testing
- [CodeQL Results](https://github.com/starman69/mcp-sanitizer/security/code-scanning) - Zero findings
- [Release Notes](https://github.com/starman69/mcp-sanitizer/releases) - Security improvements per version

## Security Reporting

If you discover a security vulnerability, please email me instead of using the public issue tracker. We follow responsible disclosure practices and will credit researchers.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Related Projects

- [Model Context Protocol](https://github.com/anthropics/model-context-protocol)
- [OWASP Input Validation](https://owasp.org/www-project-proactive-controls/v3/en/c5-validate-inputs)
- [Express Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)

---

Built with ❤️ for the MCP community. Secured with industry-standard libraries.