/**
 * Advanced Bypass Tests - Testing Sophisticated Attack Vectors
 * 
 * This test suite focuses on finding potential bypass vulnerabilities
 * that might not be caught by the standard test suite.
 */

const MCPSanitizer = require('../src/index');

console.log('🔍 Advanced Bypass Test Suite\n');
console.log('Testing sophisticated attack vectors for bypass vulnerabilities...\n');

const sanitizer = new MCPSanitizer('STRICT');

// Double/Triple Encoding Attack Vectors
const doubleEncodingTests = [
  // Double URL encoding
  '%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
  
  // Triple URL encoding
  '%25252e%25252e%25252f%25252e%25252e%25252f%25252e%25252e%25252fetc%25252fpasswd',
  
  // Mixed double encoding
  '%252e%252e%2f%252e%252e%2fetc%2fpasswd',
  
  // Unicode + URL double encoding
  '%25u002e%25u002e%252f%25u002e%25u002e%252fetc%252fpasswd',
  
  // HTML entity + URL encoding
  '%26%2346%3b%26%2346%3b%252f%26%2346%3b%26%2346%3b%252fetc%252fpasswd',
];

// Unicode Normalization Bypass Attempts
const unicodeNormalizationTests = [
  // Unicode combining characters
  'c\u0300a\u0301t\u0302 /etc/passwd',
  
  // Unicode homographs (lookalike characters)
  '\u0441\u0430\u0442 /etc/passwd', // Cyrillic 'cat'
  
  // Unicode right-to-left override
  'cat\u202e/passwd\u202d/etc',
  
  // Zero-width characters
  'ca\u200bt /et\u200bc/passwd',
  
  // Fullwidth Unicode equivalents
  '\uff43\uff41\uff54 /etc/passwd',
  
  // Mathematical alphanumeric symbols
  '\ud835\udcbc\ud835\udcb6\ud835\udccd /etc/passwd',
];

// Null Byte and Control Character Injection
const nullByteTests = [
  // Classic null byte
  'cat /etc/passwd\x00.txt',
  
  // Various null byte encodings
  'cat /etc/passwd%00.txt',
  'cat /etc/passwd\u0000.txt',
  'cat /etc/passwd&#0;.txt',
  
  // Other control characters
  'cat\x01/etc/passwd',
  'cat\x02/etc/passwd',
  'cat\x1f/etc/passwd',
  
  // Bell character and other ASCII control
  'cat\x07/etc/passwd',
  'cat\x08/etc/passwd',
  'cat\x0b/etc/passwd',
];

// Advanced Polyglot Payloads
const polyglotTests = [
  // JavaScript/HTML/SQL polyglot
  `';alert('xss')//';DROP TABLE users;--<script>alert('xss')</script>`,
  
  // Command/SQL/XSS polyglot
  `$(cat /etc/passwd)';DROP TABLE users;--<img src=x onerror=alert(1)>`,
  
  // Multi-context polyglot
  `javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>`,
  
  // PHP/JavaScript/SQL polyglot
  `<?php echo 'test'; ?>javascript:alert('xss')/*';DROP TABLE users;--*/`,
];

// WAF Bypass Techniques
const wafBypassTests = [
  // Case variation bypass attempts
  'CaT /etc/passwd',
  'cAt /ETC/passwd',
  
  // Character substitution
  'c\\x61t /etc/passwd',
  '\\143\\141\\164 /etc/passwd',
  
  // Separator variation
  'cat</etc/passwd',
  'cat</etc<passwd',
  'cat${IFS}/etc${IFS}passwd',
  
  // Quote mixing
  "c'a't /etc/passwd",
  'c"a"t /etc/passwd',
  
  // Comment injection
  'cat /*comment*/ /etc/passwd',
  'cat #comment\n /etc/passwd',
];

// Advanced SQL Injection Bypasses
const advancedSqlTests = [
  // MySQL version-specific syntax
  `/*!50000SELECT*/ * FROM users`,
  `/*M!50001SELECT*/ * FROM users`,
  
  // PostgreSQL-specific syntax
  `SELECT $tag$arbitrary string$tag$`,
  `SELECT $$arbitrary string$$`,
  
  // Oracle-specific syntax
  `SELECT 'test'||CHR(65) FROM dual`,
  
  // SQL Server-specific syntax
  `SELECT 'test'+CHAR(65)`,
  
  // NoSQL injection attempts
  `{"$where": "this.username == 'admin'"}`,
  `{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}`,
];

// Testing function with detailed logging
function testBypassVectors(vectors, testName) {
  console.log(`\n🎯 Testing ${testName}...`);
  console.log('─'.repeat(50));
  
  let bypassed = 0;
  let blocked = 0;
  let falseNegatives = [];
  
  vectors.forEach((vector, index) => {
    try {
      const result = sanitizer.sanitize(vector);
      
      if (!result.blocked && result.warnings.length === 0) {
        bypassed++;
        falseNegatives.push({ index: index + 1, vector });
        console.log(`  ❌ BYPASS DETECTED: Vector ${index + 1} passed through!`);
        console.log(`     Payload: ${vector.substring(0, 80)}${vector.length > 80 ? '...' : ''}`);
        console.log(`     Result: blocked=${result.blocked}, warnings=${result.warnings.length}`);
      } else {
        blocked++;
        console.log(`  ✅ Vector ${index + 1}: Blocked (${result.warnings.length} warnings)`);
      }
    } catch (error) {
      blocked++;
      console.log(`  ✅ Vector ${index + 1}: Error thrown (expected for malicious input)`);
    }
  });
  
  const blockRate = (blocked / vectors.length * 100).toFixed(1);
  console.log(`\n  📊 Summary: ${blocked}/${vectors.length} blocked (${blockRate}%)`);
  
  if (bypassed > 0) {
    console.log(`  🚨 CRITICAL: ${bypassed} bypass vulnerabilities detected!`);
  }
  
  return { bypassed, blocked, falseNegatives, blockRate: parseFloat(blockRate) };
}

// Timing Analysis for Side-Channel Attacks
function performTimingAnalysis() {
  console.log('\n⏱️  Detailed Timing Analysis for Side-Channel Attacks...');
  console.log('─'.repeat(50));
  
  const testCases = [
    { name: 'Safe Input', payload: 'safe input text' },
    { name: 'XSS Attack', payload: '<script>alert("xss")</script>' },
    { name: 'SQL Injection', payload: "'; DROP TABLE users; --" },
    { name: 'Command Injection', payload: 'cat /etc/passwd' },
    { name: 'Path Traversal', payload: '../../../etc/passwd' }
  ];
  
  const samples = 500;
  const results = {};
  
  testCases.forEach(testCase => {
    const times = [];
    
    // Warm-up
    for (let i = 0; i < 10; i++) {
      sanitizer.sanitize(testCase.payload);
    }
    
    // Collect timing samples
    for (let i = 0; i < samples; i++) {
      const start = process.hrtime.bigint();
      sanitizer.sanitize(testCase.payload);
      const end = process.hrtime.bigint();
      times.push(Number(end - start) / 1000000); // Convert to ms
    }
    
    // Calculate statistics
    const mean = times.reduce((a, b) => a + b) / times.length;
    const variance = times.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / times.length;
    const stdDev = Math.sqrt(variance);
    const min = Math.min(...times);
    const max = Math.max(...times);
    
    results[testCase.name] = { mean, stdDev, min, max, times };
    
    console.log(`  ${testCase.name}:`);
    console.log(`    Mean: ${mean.toFixed(3)}ms`);
    console.log(`    Std Dev: ${stdDev.toFixed(3)}ms`);
    console.log(`    Min/Max: ${min.toFixed(3)}ms / ${max.toFixed(3)}ms`);
  });
  
  // Analyze timing differences
  const baseLine = results['Safe Input'].mean;
  let suspiciousDifferences = 0;
  
  console.log('\n  🔍 Timing Difference Analysis:');
  Object.keys(results).forEach(name => {
    if (name !== 'Safe Input') {
      const diff = Math.abs(results[name].mean - baseLine);
      const diffPercent = (diff / baseLine * 100);
      console.log(`    ${name}: ${diff.toFixed(3)}ms diff (${diffPercent.toFixed(1)}%)`);
      
      if (diffPercent > 10) {
        suspiciousDifferences++;
        console.log(`      ⚠️  Significant timing difference detected!`);
      }
    }
  });
  
  return { suspiciousDifferences, results };
}

// Memory Usage Analysis
function performMemoryAnalysis() {
  console.log('\n💾 Memory Usage Analysis...');
  console.log('─'.repeat(50));
  
  const initialMemory = process.memoryUsage().heapUsed / 1024 / 1024;
  
  // Test with progressively larger payloads
  const payloadSizes = [1000, 10000, 100000, 500000];
  const memoryResults = [];
  
  payloadSizes.forEach(size => {
    const payload = 'A'.repeat(size);
    const beforeMem = process.memoryUsage().heapUsed / 1024 / 1024;
    
    // Process the payload multiple times
    for (let i = 0; i < 10; i++) {
      sanitizer.sanitize(payload);
    }
    
    // Force garbage collection if available
    if (global.gc) {
      global.gc();
    }
    
    const afterMem = process.memoryUsage().heapUsed / 1024 / 1024;
    const memoryGrowth = afterMem - beforeMem;
    
    memoryResults.push({ size, memoryGrowth });
    console.log(`  Payload size ${size}: ${memoryGrowth.toFixed(2)}MB growth`);
  });
  
  const finalMemory = process.memoryUsage().heapUsed / 1024 / 1024;
  const totalGrowth = finalMemory - initialMemory;
  
  console.log(`  Total memory growth: ${totalGrowth.toFixed(2)}MB`);
  
  return { memoryResults, totalGrowth };
}

// Main test execution
async function runAdvancedBypassTests() {
  console.log('🏁 Starting Advanced Bypass Test Suite...\n');
  
  const testResults = {
    doubleEncoding: testBypassVectors(doubleEncodingTests, 'Double/Triple Encoding Bypasses'),
    unicodeNormalization: testBypassVectors(unicodeNormalizationTests, 'Unicode Normalization Bypasses'),
    nullByte: testBypassVectors(nullByteTests, 'Null Byte & Control Character Injection'),
    polyglot: testBypassVectors(polyglotTests, 'Advanced Polyglot Payloads'),
    wafBypass: testBypassVectors(wafBypassTests, 'WAF Bypass Techniques'),
    advancedSql: testBypassVectors(advancedSqlTests, 'Advanced SQL Injection Bypasses')
  };
  
  const timingResults = performTimingAnalysis();
  const memoryResults = performMemoryAnalysis();
  
  // Compile final report
  console.log('\n' + '═'.repeat(70));
  console.log('📊 ADVANCED BYPASS TEST RESULTS');
  console.log('═'.repeat(70));
  
  let totalBypasses = 0;
  let totalTests = 0;
  let allFalseNegatives = [];
  
  Object.keys(testResults).forEach(testName => {
    const result = testResults[testName];
    totalBypasses += result.bypassed;
    totalTests += (result.bypassed + result.blocked);
    allFalseNegatives = allFalseNegatives.concat(result.falseNegatives.map(fn => ({ testName, ...fn })));
    
    console.log(`${testName}: ${result.blockRate}% blocked (${result.bypassed} bypasses)`);
  });
  
  const overallBlockRate = ((totalTests - totalBypasses) / totalTests * 100).toFixed(1);
  
  console.log('\n📈 Overall Statistics:');
  console.log(`  Total attack vectors tested: ${totalTests}`);
  console.log(`  Total bypasses detected: ${totalBypasses}`);
  console.log(`  Overall block rate: ${overallBlockRate}%`);
  
  console.log('\n⏱️  Timing Attack Assessment:');
  console.log(`  Suspicious timing differences: ${timingResults.suspiciousDifferences}`);
  
  console.log('\n💾 Memory Usage Assessment:');
  console.log(`  Total memory growth: ${memoryResults.totalGrowth.toFixed(2)}MB`);
  
  if (totalBypasses > 0) {
    console.log('\n❌ CRITICAL SECURITY FAILURES DETECTED:');
    allFalseNegatives.forEach(failure => {
      console.log(`  - ${failure.testName} vector ${failure.index}: ${failure.vector.substring(0, 60)}...`);
    });
    console.log('\n🚨 ADVANCED BYPASS TESTS FAILED - VULNERABILITIES FOUND! 🚨');
  } else {
    console.log('\n✅ ADVANCED BYPASS TESTS PASSED - NO BYPASSES DETECTED! ✅');
  }
  
  console.log('\n' + '═'.repeat(70));
  
  return {
    overallBlockRate: parseFloat(overallBlockRate),
    totalBypasses,
    totalTests,
    timingVulnerabilities: timingResults.suspiciousDifferences,
    memoryGrowth: memoryResults.totalGrowth
  };
}

// Execute tests
if (require.main === module) {
  runAdvancedBypassTests().catch(error => {
    console.error('❌ Advanced bypass tests failed:', error);
    process.exit(1);
  });
}

module.exports = { runAdvancedBypassTests };