# MCP Sanitizer Configuration System

The MCP Sanitizer configuration system provides a flexible and secure way to configure the sanitizer for different use cases and environments. It includes predefined security policies, customizable configurations, and a fluent API for easy setup.

## Table of Contents

- [Quick Start](#quick-start)
- [Security Policies](#security-policies)
- [Configuration Options](#configuration-options)
- [Usage Examples](#usage-examples)
- [API Reference](#api-reference)
- [Best Practices](#best-practices)

## Quick Start

### Using Default Configuration

```javascript
const MCPSanitizer = require('mcp-sanitizer');

// Use default configuration
const sanitizer = new MCPSanitizer();
```

### Using Security Policies

```javascript
// Use predefined security policy
const sanitizer = new MCPSanitizer('STRICT');

// Use policy with customizations
const sanitizer = new MCPSanitizer({
  policy: 'MODERATE',
  maxStringLength: 15000,
  allowedProtocols: ['https', 'mcp']
});
```

### Using Configuration Builder

```javascript
const { createConfigBuilder } = require('mcp-sanitizer/src/config');

const config = createConfigBuilder()
  .usePolicy('MODERATE')
  .maxStringLength(20000)
  .allowProtocols(['https', 'mcp'])
  .strictMode(true)
  .build();

const sanitizer = new MCPSanitizer(config);
```

## Security Policies

The MCP Sanitizer includes five predefined security policies:

### STRICT Policy
- **Use Case**: High-security environments, untrusted input
- **Protocols**: HTTPS only
- **String Length**: 1,000 characters max
- **Depth**: 3 levels max
- **File Extensions**: .txt, .json only
- **Blocking**: Medium severity and above

### MODERATE Policy
- **Use Case**: Production applications with balanced security
- **Protocols**: HTTP, HTTPS, MCP
- **String Length**: 5,000 characters max
- **Depth**: 8 levels max
- **File Extensions**: .txt, .json, .md, .csv, .yaml, .yml
- **Blocking**: High severity and above

### PERMISSIVE Policy
- **Use Case**: Trusted environments, development scenarios
- **Protocols**: HTTP, HTTPS, FTP, MCP, File
- **String Length**: 50,000 characters max
- **Depth**: 20 levels max
- **File Extensions**: Many common file types
- **Blocking**: Critical severity only

### DEVELOPMENT Policy
- **Use Case**: Development environments with debugging
- **Protocols**: HTTP, HTTPS, MCP, File
- **String Length**: 20,000 characters max
- **Depth**: 15 levels max
- **Features**: Relaxed restrictions, localhost access allowed

### PRODUCTION Policy
- **Use Case**: Production environments with security focus
- **Protocols**: HTTPS, MCP only
- **String Length**: 8,000 characters max
- **Depth**: 10 levels max
- **Features**: Enhanced security patterns, caching enabled

## Configuration Options

### Network Security

```javascript
{
  allowedProtocols: ['http', 'https', 'mcp'],
  contextSettings: {
    url: {
      allowPrivateIPs: false,
      allowLocalhostWithoutPort: false,
      maxURLLength: 2048,
      blockedDomains: [],
      allowedDomains: []
    }
  }
}
```

### Content Limits

```javascript
{
  maxStringLength: 10000,    // Maximum string length
  maxDepth: 10,              // Maximum object depth
  maxArrayLength: 1000,      // Maximum array length
  maxObjectKeys: 100         // Maximum object keys
}
```

### File System Security

```javascript
{
  allowedFileExtensions: ['.txt', '.json', '.md'],
  contextSettings: {
    filePath: {
      allowAbsolutePaths: false,
      allowedDirectories: ['./data', './uploads'],
      blockedDirectories: ['/etc', '/proc', '/sys']
    }
  }
}
```

### Pattern Detection

```javascript
{
  blockedPatterns: [
    /\$\{.*?\}|\{\{.*?\}\}/,              // Template injection
    /__proto__|constructor\.prototype/i,   // Prototype pollution
    /require\s*\(|eval\s*\(/i             // Code execution
  ],
  sqlKeywords: ['DROP', 'DELETE', 'INSERT'],
  patternDetection: {
    enableCommandInjection: true,
    enableSQLInjection: true,
    enablePrototypePollution: true,
    enableTemplateInjection: true,
    enableXSSDetection: true,
    enablePathTraversal: true
  }
}
```

### Security Settings

```javascript
{
  strictMode: false,           // Enable strict validation
  logSecurityEvents: true,     // Log security violations
  blockOnSeverity: 'critical', // Block at this severity level
}
```

## Usage Examples

### Environment-Based Configuration

```javascript
const { createRecommendedConfig } = require('mcp-sanitizer/src/config');

// Get recommended configuration for environment
const { config, metadata } = createRecommendedConfig('production', 'low');
console.log(metadata.rationale); // Why this policy was recommended

const sanitizer = new MCPSanitizer(config);
```

### Runtime Configuration Updates

```javascript
const sanitizer = new MCPSanitizer('MODERATE');

// Update configuration at runtime
sanitizer.updateConfig({
  maxStringLength: 25000,
  allowedProtocols: ['https', 'mcp']
});

// Apply new policy
sanitizer.applyPolicy('STRICT', {
  maxStringLength: 8000 // Override strict policy setting
});

// Check environment compatibility
const compatibility = sanitizer.checkEnvironmentCompatibility('production');
if (!compatibility.compatible) {
  console.log('Warnings:', compatibility.warnings);
  console.log('Recommendations:', compatibility.recommendations);
}
```

### Custom Security Patterns

```javascript
const { createConfig } = require('mcp-sanitizer/src/config');

const config = createConfig({
  blockedPatterns: [
    // Add custom patterns for your use case
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

### Policy Validation

```javascript
const { validatePolicyRequirements } = require('mcp-sanitizer/src/config');

const requirements = {
  requireHTTPS: true,
  maxStringLength: 5000,
  blockSeverity: 'medium'
};

const validation = validatePolicyRequirements(config, requirements);
if (!validation.valid) {
  console.log('Policy violations:', validation.violations);
}
```

## API Reference

### Configuration Functions

- `createConfig(options)` - Create configuration with defaults
- `createConfigFromPolicy(policyName, customizations)` - Create from policy
- `createRecommendedConfig(environment, trustLevel, customizations)` - Get recommended config
- `createConfigBuilder()` - Create fluent builder
- `mergeConfig(baseConfig, customConfig)` - Merge configurations
- `validateConfig(config)` - Validate configuration
- `getDefaultConfig()` - Get default configuration copy

### Security Policy Functions

- `getSecurityPolicy(policyName)` - Get policy by name
- `createCustomPolicy(basePolicyName, customizations)` - Create custom policy
- `getPolicyRecommendation(environment, trustLevel)` - Get policy recommendation
- `validatePolicyRequirements(policy, requirements)` - Validate policy requirements

### Utility Functions

- `getConfigSummary(config)` - Get configuration summary
- `validateEnvironmentCompatibility(config, environment)` - Check environment compatibility

### MCPSanitizer Methods

- `getConfigSummary()` - Get current configuration summary
- `updateConfig(newOptions)` - Update configuration
- `applyPolicy(policyName, customizations)` - Apply security policy
- `checkEnvironmentCompatibility(environment)` - Check environment compatibility

## Best Practices

### Security

1. **Use appropriate policies for your environment**:
   - Development: `DEVELOPMENT` or `PERMISSIVE`
   - Staging: `MODERATE` or `PRODUCTION`
   - Production: `PRODUCTION` or `STRICT`

2. **Validate configurations against requirements**:
   ```javascript
   const validation = validatePolicyRequirements(config, {
     requireHTTPS: true,
     blockSeverity: 'medium'
   });
   ```

3. **Check environment compatibility**:
   ```javascript
   const compatibility = sanitizer.checkEnvironmentCompatibility('production');
   ```

### Performance

1. **Use caching in production**:
   ```javascript
   const config = createConfig({
     performance: {
       enableCaching: true,
       maxConcurrentRequests: 100
     }
   });
   ```

2. **Set appropriate limits**:
   ```javascript
   const config = createConfig({
     maxStringLength: 10000,  // Balance security and functionality
     maxDepth: 10,           // Prevent deep nesting attacks
     performance: {
       timeoutMs: 5000       // Prevent DoS through slow processing
     }
   });
   ```

### Flexibility

1. **Use the configuration builder for complex setups**:
   ```javascript
   const config = createConfigBuilder()
     .usePolicy('MODERATE')
     .custom({ maxStringLength: 15000 })
     .patternDetection({ enableTemplateInjection: false })
     .build();
   ```

2. **Create custom policies for reuse**:
   ```javascript
   const customPolicy = createCustomPolicy('MODERATE', {
     allowedProtocols: ['https', 'mcp'],
     maxStringLength: 20000
   });
   ```

### Monitoring

1. **Enable security event logging**:
   ```javascript
   const config = createConfig({
     logSecurityEvents: true,
     blockOnSeverity: 'medium'
   });
   ```

2. **Monitor configuration summaries**:
   ```javascript
   const summary = sanitizer.getConfigSummary();
   console.log('Current limits:', summary.limits);
   console.log('Security settings:', summary.security);
   ```

For more examples, see the [configuration examples file](../../examples/configuration-examples.js).