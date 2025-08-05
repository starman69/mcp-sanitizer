# MCP Sanitizer API Documentation

## Table of Contents

- [Core Classes](#core-classes)
  - [MCPSanitizer](#mcpsanitizer)
- [Configuration](#configuration)
  - [Configuration Functions](#configuration-functions)
  - [Security Policies](#security-policies)
  - [Configuration Builder](#configuration-builder)
- [Validators](#validators)
  - [URLValidator](#urlvalidator)
  - [FilePathValidator](#filepathvalidator)
  - [CommandValidator](#commandvalidator)
  - [SQLValidator](#sqlvalidator)
- [Middleware](#middleware)
  - [Express Middleware](#express-middleware)
  - [Fastify Plugin](#fastify-plugin)
  - [Koa Middleware](#koa-middleware)
- [Utilities](#utilities)
  - [String Utilities](#string-utilities)
  - [Object Utilities](#object-utilities)
  - [Validation Utilities](#validation-utilities)
- [Pattern Detection](#pattern-detection)

## Core Classes

### MCPSanitizer

The main sanitizer class that provides comprehensive input sanitization.

#### Constructor

```javascript
new MCPSanitizer(options?)
```

**Parameters:**
- `options` (optional): Can be:
  - A configuration object
  - A security policy name (string): `'STRICT'`, `'MODERATE'`, `'PERMISSIVE'`, `'DEVELOPMENT'`, `'PRODUCTION'`
  - An object with `policy` field and customizations

**Examples:**
```javascript
// Default configuration
const sanitizer = new MCPSanitizer();

// Using security policy
const sanitizer = new MCPSanitizer('STRICT');

// Policy with customizations
const sanitizer = new MCPSanitizer({
  policy: 'MODERATE',
  maxStringLength: 15000
});

// Full configuration
const sanitizer = new MCPSanitizer({
  maxStringLength: 10000,
  maxDepth: 10,
  allowedProtocols: ['https', 'mcp'],
  blockedPatterns: [/__proto__/gi]
});
```

#### Methods

##### `sanitize(input, context?)`

Sanitizes any input data based on its type and content.

**Parameters:**
- `input`: Any data to sanitize
- `context` (optional): Object with `type` field specifying context

**Returns:**
```typescript
{
  sanitized: any;      // Sanitized data or null if blocked
  warnings: string[];  // Array of warning messages
  blocked: boolean;    // True if input was completely blocked
}
```

**Context Types:**
- `'file_path'`: Apply file path validation rules
- `'url'`: Apply URL validation rules
- `'command'`: Apply command validation rules
- `'sql'`: Apply SQL validation rules

**Example:**
```javascript
// General sanitization
const result = sanitizer.sanitize({ 
  message: '<script>alert("xss")</script>' 
});

// Context-specific sanitization
const fileResult = sanitizer.sanitize('/etc/passwd', { type: 'file_path' });
const urlResult = sanitizer.sanitize('http://localhost', { type: 'url' });
```

##### `sanitizeFilePath(filePath)`

Specialized method for sanitizing file paths.

**Parameters:**
- `filePath`: String representing a file path

**Returns:** Same as `sanitize()` method

**Example:**
```javascript
const result = sanitizer.sanitizeFilePath('../../../etc/passwd');
// { blocked: true, warnings: ['Directory traversal detected'], sanitized: null }
```

##### `sanitizeURL(url)`

Specialized method for sanitizing URLs.

**Parameters:**
- `url`: String representing a URL

**Returns:** Same as `sanitize()` method

**Example:**
```javascript
const result = sanitizer.sanitizeURL('javascript:alert(1)');
// { blocked: true, warnings: ['Dangerous protocol'], sanitized: null }
```

##### `sanitizeCommand(command)`

Specialized method for sanitizing shell commands.

**Parameters:**
- `command`: String representing a shell command

**Returns:** Same as `sanitize()` method

**Example:**
```javascript
const result = sanitizer.sanitizeCommand('ls; rm -rf /');
// { blocked: true, warnings: ['Command injection detected'], sanitized: null }
```

##### `sanitizeSQL(query)`

Specialized method for sanitizing SQL queries.

**Parameters:**
- `query`: String representing a SQL query

**Returns:** Same as `sanitize()` method

**Example:**
```javascript
const result = sanitizer.sanitizeSQL("SELECT * FROM users WHERE id = '1' OR '1'='1'");
// { blocked: true, warnings: ['SQL injection pattern detected'], sanitized: null }
```

##### `getConfigSummary()`

Get a summary of the current configuration.

**Returns:**
```typescript
{
  policy: string;
  limits: {
    maxStringLength: number;
    maxDepth: number;
    maxArrayLength: number;
    maxObjectKeys: number;
  };
  security: {
    blockOnSeverity: string;
    strictMode: boolean;
    logSecurityEvents: boolean;
  };
  patterns: {
    blockedPatternsCount: number;
    sqlKeywordsCount: number;
  };
  performance?: {
    enableCaching: boolean;
    timeoutMs: number;
  };
}
```

##### `updateConfig(newOptions)`

Update configuration at runtime.

**Parameters:**
- `newOptions`: Partial configuration object

**Example:**
```javascript
sanitizer.updateConfig({
  maxStringLength: 25000,
  strictMode: true
});
```

##### `applyPolicy(policyName, customizations?)`

Apply a security policy at runtime.

**Parameters:**
- `policyName`: Name of the security policy
- `customizations` (optional): Overrides for the policy

**Example:**
```javascript
sanitizer.applyPolicy('STRICT', {
  maxStringLength: 5000
});
```

##### `checkEnvironmentCompatibility(environment)`

Check if current configuration is suitable for an environment.

**Parameters:**
- `environment`: `'development'` | `'staging'` | `'production'`

**Returns:**
```typescript
{
  compatible: boolean;
  warnings: string[];
  recommendations: string[];
}
```

## Configuration

### Configuration Functions

#### `createConfig(options)`

Create a configuration with defaults.

**Parameters:**
- `options`: Partial configuration object

**Returns:** Complete configuration object

#### `createConfigFromPolicy(policyName, customizations?)`

Create configuration from a security policy.

**Parameters:**
- `policyName`: Name of the policy
- `customizations`: Optional overrides

**Returns:** Configuration object

#### `createRecommendedConfig(environment, trustLevel, customizations?)`

Get recommended configuration for your environment.

**Parameters:**
- `environment`: `'development'` | `'staging'` | `'production'`
- `trustLevel`: `'high'` | `'medium'` | `'low'`
- `customizations`: Optional overrides

**Returns:**
```typescript
{
  config: Configuration;
  metadata: {
    policy: string;
    environment: string;
    trustLevel: string;
    rationale: string;
  };
}
```

### Security Policies

#### Available Policies

- **STRICT**: High-security environments, untrusted input
- **MODERATE**: Balanced production security
- **PERMISSIVE**: Trusted environments
- **DEVELOPMENT**: Development with debugging
- **PRODUCTION**: Production environments

#### `getSecurityPolicy(policyName)`

Get a security policy by name.

**Parameters:**
- `policyName`: Name of the policy

**Returns:** Policy configuration object

### Configuration Builder

#### `createConfigBuilder()`

Create a fluent configuration builder.

**Returns:** ConfigurationBuilder instance

**Example:**
```javascript
const config = createConfigBuilder()
  .usePolicy('MODERATE')
  .maxStringLength(20000)
  .allowProtocols(['https', 'mcp'])
  .allowFileExtensions(['.txt', '.json', '.md'])
  .blockOnSeverity('high')
  .strictMode(true)
  .patternDetection({
    enableCommandInjection: true,
    enableSQLInjection: true,
    enablePrototypePollution: true
  })
  .build();
```

## Validators

### URLValidator

Validates and sanitizes URLs.

#### Constructor

```javascript
new URLValidator(config?)
```

#### Methods

##### `validate(url, options?)`

Validate a URL asynchronously.

**Returns:**
```typescript
{
  isValid: boolean;
  sanitized: string | null;
  warnings: string[];
  severity: 'low' | 'medium' | 'high' | 'critical' | null;
  metadata: {
    originalUrl: string;
    parsedUrl: object | null;
    protocol: string | null;
    hostname: string | null;
    port: string | null;
    isPrivateIP: boolean;
    detectedPatterns: string[];
    validatorCheck?: boolean;
  };
}
```

##### `sanitize(url, options?)`

Sanitize a URL, attempting to fix issues.

##### `isURL(url, options?)`

Check if string is a valid URL using validator.js.

##### `isHTTPS(url)`

Check if URL uses HTTPS protocol.

##### `isIP(hostname)`

Check if hostname is an IP address.

##### `isFQDN(hostname)`

Check if hostname is a fully qualified domain name.

### FilePathValidator

Validates and sanitizes file paths.

#### Constructor

```javascript
new FilePathValidator(config?)
```

#### Methods

##### `validate(filePath, options?)`

Validate a file path asynchronously.

##### `sanitize(filePath, options?)`

Sanitize a file path, attempting to fix issues.

##### `sanitizeFilename(filename, options?)`

Sanitize a filename using sanitize-filename library.

**Parameters:**
- `filename`: Filename to sanitize
- `options`: Object with `replacement` character (default: '_')

##### `isPathInside(childPath, parentPath)`

Check if a path is inside another path.

##### `isPathSafe(filePath, allowedPaths)`

Check if a path is within allowed paths.

##### `extractSafeFilename(filePath)`

Extract and sanitize just the filename from a path.

### CommandValidator

Validates and sanitizes shell commands.

#### Constructor

```javascript
new CommandValidator(config?)
```

#### Methods

##### `validate(command, options?)`

Validate a shell command.

##### `sanitize(command, options?)`

Sanitize a shell command.

##### `quote(args)`

Quote command arguments safely using shell-quote.

**Parameters:**
- `args`: Array of command arguments

**Returns:** Quoted command string

##### `parse(command)`

Parse a command string into arguments.

**Parameters:**
- `command`: Command string

**Returns:** Array of parsed arguments

##### `buildSafeCommand(baseCommand, args)`

Build a safe command with quoted arguments.

### SQLValidator

Validates and sanitizes SQL queries.

#### Constructor

```javascript
new SQLValidator(config?)
```

#### Methods

##### `validate(query, options?)`

Validate a SQL query.

##### `sanitize(query, options?)`

Sanitize a SQL query.

##### `escapeValue(value)`

Escape a SQL value using sqlstring.

**Parameters:**
- `value`: Any value to escape

**Returns:** Escaped SQL string

##### `escapeIdentifier(identifier)`

Escape a SQL identifier (table/column name).

**Parameters:**
- `identifier`: Identifier to escape

**Returns:** Escaped identifier with backticks

##### `format(sql, values)`

Format a SQL query with placeholders.

**Parameters:**
- `sql`: SQL query with ? placeholders
- `values`: Array of values to insert

**Returns:** Formatted SQL query

## Middleware

### Express Middleware

#### `createExpressMiddleware(options?)`

Create Express.js middleware.

**Parameters:**
- `options`: Middleware configuration

**Options:**
```typescript
{
  policy?: string;
  mode?: 'sanitize' | 'block';
  skipPaths?: string[];
  customSanitizer?: MCPSanitizer;
  logLevel?: 'none' | 'warn' | 'info' | 'debug';
}
```

#### `mcpSanitizationMiddleware`

Default Express middleware instance.

### Fastify Plugin

#### `createFastifyPlugin(options?)`

Create Fastify plugin.

**Parameters:**
- `options`: Plugin configuration

**Usage:**
```javascript
fastify.register(createFastifyPlugin({
  policy: 'MODERATE'
}));
```

### Koa Middleware

#### `createKoaMiddleware(options?)`

Create Koa middleware.

**Parameters:**
- `options`: Middleware configuration

**Usage:**
```javascript
app.use(createKoaMiddleware({
  policy: 'STRICT'
}));
```

### Universal Middleware

#### `createMCPMiddleware(app?, options?)`

Create middleware with auto-detection.

**Parameters:**
- `app`: Express, Fastify, or Koa instance (optional)
- `options`: Middleware configuration

**Returns:** Appropriate middleware for the framework

## Utilities

### String Utilities

#### `htmlEncode(str)`

HTML entity encode a string using escape-html.

**Parameters:**
- `str`: String to encode

**Returns:** HTML-encoded string

#### `truncateString(str, maxLength)`

Truncate a string to maximum length.

#### `isValidString(str, maxLength?)`

Check if value is a valid string.

### Object Utilities

#### `deepClone(obj, maxDepth?)`

Deep clone an object with depth limit.

#### `flattenObject(obj, prefix?)`

Flatten nested object to dot notation.

#### `sanitizeObjectKeys(obj, maxDepth?)`

Sanitize object keys recursively.

#### `removeCircularReferences(obj)`

Remove circular references from object.

### Validation Utilities

#### `isValidProtocol(protocol, allowedProtocols)`

Check if protocol is allowed.

#### `isValidFileExtension(filename, allowedExtensions)`

Check if file extension is allowed.

#### `containsPattern(str, patterns)`

Check if string contains any blocked pattern.

#### `isWithinLimits(value, limits)`

Check if value is within configured limits.

## Pattern Detection

### `detectAllPatterns(input)`

Detect all security patterns in input.

**Parameters:**
- `input`: String to check

**Returns:**
```typescript
{
  detected: boolean;
  patterns: string[];
  severity: 'low' | 'medium' | 'high' | 'critical';
  details: Array<{
    type: string;
    pattern: string;
    severity: string;
    match: string;
  }>;
}
```

### Pattern Types

- **Command Injection**: Shell metacharacters and dangerous commands
- **SQL Injection**: SQL keywords and injection patterns
- **Template Injection**: Template engine patterns
- **Prototype Pollution**: `__proto__` and constructor manipulation
- **XSS**: Script tags and JavaScript execution
- **Path Traversal**: Directory traversal patterns

### Custom Patterns

Add custom patterns via configuration:

```javascript
const sanitizer = new MCPSanitizer({
  blockedPatterns: [
    /custom-pattern/gi,
    /another-pattern/
  ]
});
```

## Error Handling

All methods handle errors gracefully:
- Invalid input types return appropriate warnings
- Circular references are handled automatically
- Stack overflow prevention via depth limits
- Timeout protection for long operations

## Performance Considerations

- String operations use C++ backed libraries where available
- Caching can be enabled for repeated validations
- Depth and size limits prevent DoS attacks
- Async operations for potentially slow validations

## Security Best Practices

1. Always use appropriate context when sanitizing
2. Log security events for monitoring
3. Use strict policies for untrusted input
4. Regularly update the library
5. Combine with other security measures
6. Test with your specific use cases

