# MCP Sanitizer Examples

This directory contains example implementations and testing tools for the MCP Sanitizer library.

## 🚀 Examples Overview

### 1. `mcp-server-basic.js` - Interactive MCP-Style Server
A standalone server demonstrating MCP security patterns without external dependencies.

**Features:**
- Interactive command-line interface
- File operations with path traversal prevention
- URL validation with SSRF protection
- Command and SQL injection detection
- Built-in security testing suite (8 attack vectors)

**Usage:**
```bash
# Run interactive server
node examples/mcp-server-basic.js

# Commands:
# test     - Run security test suite
# read <path> - Read a file safely
# ls [path] - List directory contents
# url <url> - Validate a URL
# cmd <command> - Check command safety
# sql <query> - Check SQL query safety
```

### 2. `mcp-server.js` - Full MCP SDK Integration Example
Example for integrating with the official MCP SDK (requires `@modelcontextprotocol/sdk`).

**Note:** Requires MCP SDK installation:
```bash
npm install @modelcontextprotocol/sdk
```

**Features:**
- Full MCP protocol implementation
- Tool definitions with input schemas
- Comprehensive security for all tool inputs
- Production-ready patterns for MCP servers

**Usage:**
```bash
# With MCP SDK installed
node examples/mcp-server.js

# Or use with MCP inspector
npx @modelcontextprotocol/inspector examples/mcp-server.js
```

### 3. `test-server.js` - HTTP Testing Server
An HTTP server with web UI for testing sanitization features.

**Features:**
- Interactive web interface at http://localhost:3000
- RESTful API for testing all sanitization contexts
- Pre-defined attack vectors
- Real-time testing of security features

**Usage:**
```bash
node examples/test-server.js
# Open browser to http://localhost:3000
```

### 4. `security-bypass-demo.js` - Red Team Assessment
Demonstrates the security vulnerabilities found in v1.0.0 and validates they're fixed in v1.1.0.

**Features:**
- Tests 10 critical attack vectors
- Shows vulnerability score (0% in v1.1.0)
- Formatted as professional security assessment
- Can simulate v1.0.0 vulnerabilities with flag

**Usage:**
```bash
# Test current version (should block all attacks)
node examples/security-bypass-demo.js

# Simulate v1.0.0 vulnerabilities
node examples/security-bypass-demo.js --v1.0.0
```

### 5. `edge-case-validation.js` - Edge Case Testing
Validates that specific edge cases identified during security analysis are properly handled.

**Features:**
- Tests newline command injection
- Tests Windows system paths
- Tests UNC network paths
- Confirms all edge cases are blocked

**Usage:**
```bash
node examples/edge-case-validation.js
```

## 🔒 Security Testing

To comprehensively test the security features:

1. **Run the test server:**
   ```bash
   node examples/test-server.js
   ```

2. **Test with curl:**
   ```bash
   # Test path traversal
   curl -X POST http://localhost:3000/sanitize/file \
     -H "Content-Type: application/json" \
     -d '{"path": "../../../etc/passwd"}'

   # Test command injection
   curl -X POST http://localhost:3000/sanitize/command \
     -H "Content-Type: application/json" \
     -d '{"command": "ls; cat /etc/passwd"}'

   # Test SQL injection
   curl -X POST http://localhost:3000/sanitize/sql \
     -H "Content-Type: application/json" \
     -d '{"query": "SELECT * FROM users WHERE id = 1 OR 1=1"}'
   ```

3. **Run the security validation:**
   ```bash
   node examples/security-bypass-demo.js
   ```

## 📊 Expected Results

All attack vectors should be **BLOCKED** with v1.1.0:
- Path traversal attempts: ✅ Blocked
- Command injection: ✅ Blocked
- SQL injection: ✅ Blocked
- XSS attempts: ✅ Blocked
- Template injection: ✅ Blocked
- Prototype pollution: ✅ Blocked
- Unicode/encoding bypasses: ✅ Blocked
- Null byte injection: ✅ Blocked

## 🛠️ Integration Guide

### For MCP Servers

Use the pattern from `mcp-server.js`:

```javascript
const MCPSanitizer = require('mcp-sanitizer');
const sanitizer = new MCPSanitizer('PRODUCTION');

// In your tool handler
const result = sanitizer.sanitize(userInput, { type: 'file_path' });
if (result.blocked) {
  return { error: 'Security policy violation', warnings: result.warnings };
}
// Use result.sanitized safely
```

### For Express/Web APIs

Use the middleware approach:

```javascript
const { createMCPMiddleware } = require('mcp-sanitizer');

app.use(createMCPMiddleware({
  policy: 'PRODUCTION',
  skipPaths: ['/health', '/metrics']
}));
```

## ⚠️ Important Notes

1. **Test Server**: The `test-server.js` is for testing only. Do not expose it to the internet.
2. **Security Policies**: Always use `PRODUCTION` or `STRICT` policy for real applications.
3. **Path Restrictions**: Always validate paths are within allowed directories after sanitization.
4. **SSRF Prevention**: Block requests to internal IPs and metadata endpoints.
5. **Logging**: Log all blocked attempts for security monitoring.

## 📝 License

These examples are part of the MCP Sanitizer project under MIT License.