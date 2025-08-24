/**
 * Performance benchmarks for security enhancements
 * Target: <10ms per inline sanitization operation
 */

const {
  detectDirectionalOverrides,
  detectNullBytes,
  detectMultipleUrlEncoding,
  detectPostgresDollarQuotes,
  detectCyrillicHomographs,
  handleEmptyStrings,
  comprehensiveSecurityAnalysis,
  DIRECTIONAL_OVERRIDES
} = require('../src/utils/security-enhancements');

describe('Security Performance Benchmarks', () => {
  
  const testInputs = [
    'normal string input',
    `malicious${DIRECTIONAL_OVERRIDES.RLO}attack`,
    '/path\x00/../etc/passwd',
    '%252E%252E%252F',
    'аpple.com',
    "SELECT $$content$$",
    '',
    'very'.repeat(1000) + ' long string'
  ];

  test('individual security checks should complete within performance target', () => {
    const results = [];
    
    for (const input of testInputs) {
      const start = process.hrtime.bigint();
      
      // Run individual checks
      detectDirectionalOverrides(input);
      detectNullBytes(input);
      detectMultipleUrlEncoding(input);
      detectPostgresDollarQuotes(input);
      detectCyrillicHomographs(input);
      handleEmptyStrings(input, {});
      
      const end = process.hrtime.bigint();
      const durationMs = Number(end - start) / 1_000_000;
      results.push(durationMs);
    }
    
    const avgTime = results.reduce((a, b) => a + b, 0) / results.length;
    const maxTime = Math.max(...results);
    
    console.log(`Average time per batch: ${avgTime.toFixed(2)}ms`);
    console.log(`Maximum time per batch: ${maxTime.toFixed(2)}ms`);
    
    // Each batch runs 6 checks, so individual check time:
    const avgPerCheck = avgTime / 6;
    console.log(`Average time per individual check: ${avgPerCheck.toFixed(2)}ms`);
    
    expect(avgPerCheck).toBeLessThan(2); // <2ms per individual check
    expect(maxTime).toBeLessThan(15); // <15ms for full batch
  });

  test('comprehensive analysis should meet performance target', async () => {
    const results = [];
    
    for (const input of testInputs) {
      const start = process.hrtime.bigint();
      
      await comprehensiveSecurityAnalysis(input, {
        ensureTimingConsistency: false // Disable for accurate benchmarking
      });
      
      const end = process.hrtime.bigint();
      const durationMs = Number(end - start) / 1_000_000;
      results.push(durationMs);
    }
    
    const avgTime = results.reduce((a, b) => a + b, 0) / results.length;
    const maxTime = Math.max(...results);
    
    console.log(`Comprehensive analysis - Average: ${avgTime.toFixed(2)}ms`);
    console.log(`Comprehensive analysis - Maximum: ${maxTime.toFixed(2)}ms`);
    
    expect(avgTime).toBeLessThan(10); // <10ms average
    expect(maxTime).toBeLessThan(20); // <20ms maximum
  });

  test('bulk processing performance', () => {
    const bulkInputs = Array(100).fill(0).map((_, i) => `test input ${i}`);
    
    const start = process.hrtime.bigint();
    
    for (const input of bulkInputs) {
      detectDirectionalOverrides(input);
      detectNullBytes(input);
      detectCyrillicHomographs(input);
    }
    
    const end = process.hrtime.bigint();
    const totalTime = Number(end - start) / 1_000_000;
    const avgPerInput = totalTime / bulkInputs.length;
    
    console.log(`Bulk processing - Total: ${totalTime.toFixed(2)}ms for 100 inputs`);
    console.log(`Bulk processing - Average per input: ${avgPerInput.toFixed(2)}ms`);
    
    expect(avgPerInput).toBeLessThan(1); // <1ms per input for bulk processing
    expect(totalTime).toBeLessThan(100); // <100ms total for 100 inputs
  });

  test('memory usage should be minimal', () => {
    const initialMemory = process.memoryUsage().heapUsed;
    
    // Process many inputs to check for memory leaks
    for (let i = 0; i < 1000; i++) {
      const testInput = `test input ${i} with various content`;
      detectDirectionalOverrides(testInput);
      detectNullBytes(testInput);
      detectCyrillicHomographs(testInput);
    }
    
    // Force garbage collection if available
    if (global.gc) {
      global.gc();
    }
    
    const finalMemory = process.memoryUsage().heapUsed;
    const memoryIncrease = finalMemory - initialMemory;
    const memoryIncreaseKB = memoryIncrease / 1024;
    
    console.log(`Memory increase: ${memoryIncreaseKB.toFixed(2)}KB`);
    
    // Should not increase memory by more than 1MB for 1000 operations
    expect(memoryIncreaseKB).toBeLessThan(1024);
  });

  test('no performance regression with legitimate content', () => {
    const legitimateInputs = [
      'user@example.com',
      'https://www.google.com/search?q=test',
      'SELECT * FROM users WHERE id = 1',
      '/home/user/documents/file.txt',
      'The quick brown fox jumps over the lazy dog',
      JSON.stringify({ key: 'value', number: 123, array: [1, 2, 3] })
    ];
    
    const times = [];
    
    for (const input of legitimateInputs) {
      const start = process.hrtime.bigint();
      
      // Run all checks
      detectDirectionalOverrides(input);
      detectNullBytes(input);
      detectMultipleUrlEncoding(input);
      detectPostgresDollarQuotes(input);
      detectCyrillicHomographs(input);
      handleEmptyStrings(input);
      
      const end = process.hrtime.bigint();
      times.push(Number(end - start) / 1_000_000);
    }
    
    const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
    console.log(`Legitimate content processing time: ${avgTime.toFixed(2)}ms`);
    
    // Should be very fast for legitimate content (no complex processing needed)
    expect(avgTime).toBeLessThan(5);
  });
});