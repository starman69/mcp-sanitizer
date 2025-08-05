/**
 * MCP Sanitizer Configuration Examples
 * 
 * This file demonstrates various ways to configure the MCP Sanitizer
 * using the new configuration system with security policies.
 */

const MCPSanitizer = require('../src/index');
const { 
  createConfig, 
  createConfigFromPolicy, 
  createConfigBuilder,
  createRecommendedConfig,
  POLICY_NAMES
} = require('../src/config');

console.log('=== MCP Sanitizer Configuration Examples ===\n');

// Example 1: Using default configuration
console.log('1. Default Configuration:');
const defaultSanitizer = new MCPSanitizer();
console.log('Default config summary:', defaultSanitizer.getConfigSummary());
console.log();

// Example 2: Using predefined security policies
console.log('2. Security Policy Examples:');
console.log('Available policies:', POLICY_NAMES);

// Strict policy for high-security environments
const strictSanitizer = new MCPSanitizer('STRICT');
console.log('Strict policy summary:', strictSanitizer.getConfigSummary());

// Moderate policy for balanced security
const moderateSanitizer = new MCPSanitizer('MODERATE');
console.log('Moderate policy summary:', moderateSanitizer.getConfigSummary());

// Development policy for development environments
const devSanitizer = new MCPSanitizer('DEVELOPMENT');
console.log('Development policy summary:', devSanitizer.getConfigSummary());
console.log();

// Example 3: Using policy with customizations
console.log('3. Policy with Customizations:');
const customSanitizer = new MCPSanitizer({
  policy: 'MODERATE',
  maxStringLength: 15000,
  allowedProtocols: ['https', 'mcp'],
  allowedFileExtensions: ['.txt', '.json', '.md', '.yaml']
});
console.log('Custom config summary:', customSanitizer.getConfigSummary());
console.log();

// Example 4: Using Configuration Builder (Fluent API)
console.log('4. Configuration Builder (Fluent API):');
const builderConfig = createConfigBuilder()
  .usePolicy('MODERATE')
  .maxStringLength(20000)
  .allowProtocols(['https', 'mcp'])
  .allowFileExtensions(['.txt', '.json', '.md', '.csv', '.yaml'])
  .blockOnSeverity('high')
  .strictMode(true)
  .patternDetection({
    enableCommandInjection: true,
    enableSQLInjection: true,
    enablePrototypePollution: true,
    enableTemplateInjection: false // Disable for flexibility
  })
  .build();

const builderSanitizer = new MCPSanitizer(builderConfig);
console.log('Builder config summary:', builderSanitizer.getConfigSummary());
console.log();

// Example 5: Environment-based Recommendations
console.log('5. Environment-based Configuration:');

// Development environment with high trust
const devRecommendation = createRecommendedConfig('development', 'high');
console.log('Development recommendation:', devRecommendation.metadata);

// Production environment with low trust
const prodRecommendation = createRecommendedConfig('production', 'low');
console.log('Production recommendation:', prodRecommendation.metadata);
console.log();

// Example 6: Runtime Configuration Changes
console.log('6. Runtime Configuration Changes:');
const runtimeSanitizer = new MCPSanitizer('MODERATE');

console.log('Original config:', runtimeSanitizer.getConfigSummary().limits);

// Update configuration at runtime
runtimeSanitizer.updateConfig({
  maxStringLength: 25000,
  maxDepth: 15
});

console.log('Updated config:', runtimeSanitizer.getConfigSummary().limits);

// Apply new policy at runtime
runtimeSanitizer.applyPolicy('STRICT', {
  maxStringLength: 5000 // Override strict policy's string length
});

console.log('After policy change:', runtimeSanitizer.getConfigSummary().limits);
console.log();

// Example 7: Environment Compatibility Check
console.log('7. Environment Compatibility Check:');
const prodSanitizer = new MCPSanitizer('DEVELOPMENT');
const compatibility = prodSanitizer.checkEnvironmentCompatibility('production');

console.log('Development config in production environment:');
console.log('Compatible:', compatibility.compatible);
console.log('Warnings:', compatibility.warnings);
console.log('Recommendations:', compatibility.recommendations);
console.log();

// Example 8: Sanitization with Different Configurations
console.log('8. Sanitization Behavior Comparison:');

const testData = {
  message: 'Hello <script>alert("xss")</script> world',
  command: 'ls -la; rm -rf /',
  url: 'http://localhost:3000/api',
  query: 'SELECT * FROM users WHERE id = 1 OR 1=1'
};

console.log('Test data:', testData);
console.log();

// Test with different policies
const policies = ['PERMISSIVE', 'MODERATE', 'STRICT'];

for (const policy of policies) {
  console.log(`Testing with ${policy} policy:`);
  const sanitizer = new MCPSanitizer(policy);
  
  try {
    const result = sanitizer.sanitize(testData);
    console.log('  Result:', result.blocked ? 'BLOCKED' : 'ALLOWED');
    if (result.warnings.length > 0) {
      console.log('  Warnings:', result.warnings);
    }
    if (result.sanitized && !result.blocked) {
      console.log('  Sanitized data sample:', {
        message: result.sanitized.message,
        hasCommand: 'command' in result.sanitized,
        hasUrl: 'url' in result.sanitized,
        hasQuery: 'query' in result.sanitized
      });
    }
  } catch (error) {
    console.log('  Error:', error.message);
  }
  console.log();
}

// Example 9: Custom Security Patterns
console.log('9. Custom Security Patterns:');
const customPatternConfig = createConfig({
  blockedPatterns: [
    // Default patterns plus custom ones
    /\$\{.*?\}|\{\{.*?\}\}|<%.*?%>/,
    /__proto__|constructor\.prototype|prototype\.constructor/i,
    /require\s*\(|import\s*\(|eval\s*\(|Function\s*\(/i,
    
    // Custom patterns for specific use case
    /bitcoin|cryptocurrency|wallet/i,  // Block crypto-related content
    /password|secret|token/i,          // Block sensitive keywords
    /\b\d{16}\b/,                      // Block credit card numbers
  ],
  sqlKeywords: [
    // Default SQL keywords plus custom ones
    'DROP', 'DELETE', 'INSERT', 'UPDATE', 'CREATE', 'ALTER',
    'UNION', '--', '/*', '*/', 'xp_', 'sp_',
    
    // Custom SQL keywords for specific database
    'MERGE', 'UPSERT', 'BULK', 'LOAD',
  ]
});

const customPatternSanitizer = new MCPSanitizer(customPatternConfig);
console.log('Custom patterns config:', customPatternSanitizer.getConfigSummary().patterns);

// Test custom patterns
const customTestData = {
  message: 'My bitcoin wallet address is sensitive',
  payment: 'Credit card: 1234567890123456',
  query: 'MERGE INTO users SELECT * FROM temp'
};

console.log('Testing custom patterns:');
try {
  const result = customPatternSanitizer.sanitize(customTestData);
  console.log('Result:', result.blocked ? 'BLOCKED' : 'ALLOWED');
  if (result.warnings.length > 0) {
    console.log('Warnings:', result.warnings);
  }
} catch (error) {
  console.log('Error:', error.message);
}
console.log();

// Example 10: Performance Configuration
console.log('10. Performance Configuration:');
const performanceConfig = createConfig({
  performance: {
    timeoutMs: 2000,
    maxConcurrentRequests: 50,
    enableCaching: true
  },
  maxStringLength: 50000, // Large strings allowed
  maxDepth: 20,           // Deep nesting allowed
  maxArrayLength: 10000,  // Large arrays allowed
  maxObjectKeys: 1000     // Many object keys allowed
});

const performanceSanitizer = new MCPSanitizer(performanceConfig);
console.log('Performance config:', performanceSanitizer.getConfigSummary().performance);
console.log();

console.log('=== Configuration Examples Complete ===');

// Export for use in other examples
module.exports = {
  defaultSanitizer,
  strictSanitizer,
  moderateSanitizer,
  devSanitizer,
  customSanitizer,
  builderSanitizer
};