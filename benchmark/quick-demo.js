#!/usr/bin/env node
/**
 * Quick Benchmark Demo
 * 
 * Demonstrates the MCP Sanitizer's security and performance
 * without running the full benchmark suite.
 */

const MCPSanitizer = require('../src/index');

console.log('🚀 MCP Sanitizer - Quick Benchmark Demo\n');
console.log('=' .repeat(60));

// Initialize sanitizer
const sanitizer = new MCPSanitizer('STRICT');

// Test vectors
const testCases = [
  // XSS
  { input: '<script>alert(1)</script>', type: 'xss', name: 'Script injection' },
  { input: '<img src=x onerror="alert(1)">', type: 'xss', name: 'Event handler XSS' },
  
  // SQL Injection
  { input: "'; DROP TABLE users; --", type: 'sql', name: 'SQL injection' },
  { input: "' OR '1'='1", type: 'sql', name: 'SQL authentication bypass' },
  
  // Command Injection
  { input: 'cat /etc/passwd', type: 'command', name: 'Command injection' },
  { input: 'ls; rm -rf /', type: 'command', name: 'Command chaining' },
  
  // Path Traversal
  { input: '../../../etc/passwd', type: 'file_path', name: 'Path traversal' },
  { input: '..\\..\\windows\\system32', type: 'file_path', name: 'Windows path traversal' },
  
  // NoSQL Injection
  { input: '{"$ne": null}', type: 'nosql', name: 'NoSQL injection' },
  
  // Unicode Attack
  { input: 'аdmin', type: 'unicode', name: 'Cyrillic homograph (а is Cyrillic)' },
];

console.log('\n🔒 SECURITY VALIDATION\n');
console.log('-'.repeat(60));

let blocked = 0;
let total = 0;
const timings = [];

testCases.forEach(({ input, type, name }) => {
  const start = process.hrtime.bigint();
  const result = sanitizer.sanitize(input, { type });
  const end = process.hrtime.bigint();
  const timeMs = Number(end - start) / 1000000;
  
  timings.push(timeMs);
  total++;
  
  if (result.blocked) {
    blocked++;
    console.log(`✅ ${name}: BLOCKED (${timeMs.toFixed(2)}ms)`);
  } else {
    console.log(`❌ ${name}: PASSED (SECURITY ISSUE!)`);
  }
});

console.log('\n' + '='.repeat(60));
console.log('📊 RESULTS SUMMARY\n');
console.log(`Security Coverage: ${blocked}/${total} attacks blocked (${(blocked/total*100).toFixed(1)}%)`);
console.log(`Average Processing: ${(timings.reduce((a,b) => a+b, 0) / timings.length).toFixed(2)}ms`);
console.log(`Max Processing: ${Math.max(...timings).toFixed(2)}ms`);
console.log(`Min Processing: ${Math.min(...timings).toFixed(2)}ms`);

// Performance test with safe inputs
console.log('\n⚡ PERFORMANCE TEST (Safe Inputs)\n');
console.log('-'.repeat(60));

const safeInputs = [
  'Hello world',
  'user@example.com',
  '/home/user/documents/file.txt',
  'SELECT * FROM users WHERE id = 1',
  'echo "Hello"'
];

const iterations = 1000;
console.log(`Running ${iterations} iterations per input...`);

safeInputs.forEach((input, idx) => {
  const start = process.hrtime.bigint();
  
  for (let i = 0; i < iterations; i++) {
    sanitizer.sanitize(input);
  }
  
  const end = process.hrtime.bigint();
  const totalMs = Number(end - start) / 1000000;
  const avgMs = totalMs / iterations;
  const opsPerSec = Math.round(1000 / avgMs);
  
  console.log(`Input ${idx + 1}: ${avgMs.toFixed(3)}ms avg, ~${opsPerSec.toLocaleString()} ops/sec`);
});

console.log('\n' + '='.repeat(60));
console.log('✅ Benchmark demo complete!\n');
console.log('For full benchmarks, run:');
console.log('  node benchmark/advanced-security-benchmark.js');
console.log('  node benchmark/library-performance.js');
console.log('  node benchmark/skip-paths-performance.js');
console.log('=' .repeat(60));