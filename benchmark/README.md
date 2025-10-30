# MCP Sanitizer - Performance & Security Benchmarks

## 🎯 Benchmarking Philosophy

**Security First, Performance Second, Developer Experience Third**

This directory contains comprehensive benchmarks for the MCP Sanitizer library. These benchmarks ensure our security implementations maintain excellent performance while prioritizing security integrity above all else.

## ⚠️ Critical Security Principles

> **Security is not negotiable**. Performance optimizations must never compromise security.
> 
> - False negatives (missed attacks) are unacceptable
> - Memory usage must remain bounded during attacks
> - Response times should be consistent to mitigate timing attacks
> - Every optimization must pass security validation

---

## 📊 Benchmark Scripts

### 1. `library-performance.js`

**Purpose**: Validates the performance of industry-standard security libraries versus custom implementations.

**What it measures**:
- **HTML Encoding**: `escape-html` library vs regex-based encoding
- **SQL Escaping**: `sqlstring` library vs custom SQL escape functions
- **Command Escaping**: `shell-quote` library vs custom shell escaping
- **Unicode Normalization**: `unorm` library performance characteristics

**Why this matters**: 
- Validates our decision to use battle-tested security libraries
- Ensures we're not sacrificing security for marginal performance gains
- Provides baseline performance metrics for security operations
- Demonstrates that proper security doesn't require poor performance

**Run it**:
```bash
node benchmark/library-performance.js
```

**Expected output**:
- Operations per second for each approach
- Relative performance comparison
- Memory usage statistics
- Security validation confirmation

### 2. `skip-paths-performance.js`

**Purpose**: Benchmarks the middleware path-skipping optimization for health checks and metrics endpoints.

**What it measures**:
- Path matching with various configuration sizes (50-5000 paths)
- O(n) linear search vs O(1) hash lookup vs O(log n) tree structures
- String exact matching vs prefix matching vs RegExp patterns
- Memory usage and cache efficiency
- Real-world request routing scenarios

**Why this matters**:
- Ensures path skipping doesn't become a bottleneck
- Validates that optimization doesn't introduce security vulnerabilities
- Confirms performance scales appropriately with configuration size
- Demonstrates efficient handling of non-security-critical paths

**Run it**:
```bash
node benchmark/skip-paths-performance.js
```

**Key metrics**:
- Microseconds per path check
- Memory overhead per configured path
- Cache hit/miss ratios
- Performance degradation curve

### 3. `advanced-security-benchmark.js` 🔐

**Purpose**: Comprehensive security validation against real-world attack vectors.

**What it tests**:
- **XSS Vectors**: DOM-based, attribute injection, CSS injection, polyglot payloads
- **SQL Injection**: Blind, time-based, second-order, database-specific variants
- **Command Injection**: Shell metacharacters, environment variables, Unicode bypass
- **Path Traversal**: Encoded sequences, Windows/Unix paths, symlink attacks
- **NoSQL Injection**: MongoDB operators, JSON-based attacks
- **Unicode Attacks**: Homographs, normalization bypasses, directional overrides

**Security validation criteria**:
- Zero false negatives (all attacks must be detected)
- Bounded memory usage (prevents DoS)
- Consistent processing time (mitigates timing attacks)
- Comprehensive attack coverage

**Run it**:
```bash
node benchmark/advanced-security-benchmark.js
```

⚠️ **WARNING**: This benchmark uses REAL attack vectors. Failures indicate actual security vulnerabilities.

### 4. `quick-demo.js` 🎯

**Purpose**: Quick demonstration of security validation and performance without running full benchmark suite.

**What it tests**:
- 10 common attack vectors across all categories
- Processing time for each attack
- Performance with safe inputs (operations per second)

**Why this matters**:
- Quick validation that the sanitizer is working correctly
- Immediate feedback on security and performance
- Good starting point before running full benchmarks

**Run it**:
```bash
node benchmark/quick-demo.js
```

**Expected runtime**: ~2 seconds (vs 2+ minutes for full benchmarks)

---

## 📈 Performance Benchmarking Guide

### Running Benchmarks Effectively

#### 1. Environment Preparation
```bash
# Ensure clean environment
npm ci                          # Clean install dependencies
node --version                  # Document Node.js version
```

#### 2. Warm-up Considerations
```javascript
// Always include warm-up runs to:
// - Populate V8 optimization caches
// - Stabilize memory allocation
// - Eliminate JIT compilation variance
```

#### 3. Statistical Significance
- Run multiple iterations (minimum 100)
- Report percentiles (p50, p95, p99) not just averages
- Include standard deviation
- Document margin of error

### Key Performance Metrics

#### Response Time Distribution
```
Percentile | Target    | Actual    | Status
-----------|-----------|-----------|--------
p50        | < 0.5ms   | 0.28ms    | ✅ Pass
p95        | < 2ms     | 0.84ms    | ✅ Pass
p99        | < 5ms     | 2.39ms    | ✅ Pass
p99.9      | < 10ms    | 3.94ms    | ✅ Pass
```

#### Throughput Characteristics
- **Sustained load**: Operations per second under continuous load
- **Burst capacity**: Maximum spike handling capability
- **Degradation curve**: Performance at 50%, 75%, 100% capacity

#### Resource Utilization
- **Memory footprint**: Base + per-request overhead
- **CPU efficiency**: Cycles per operation
- **GC pressure**: Allocation rate and pause frequency

---

## 🔬 Security Benchmarking Guide

### Attack Vector Coverage

The benchmark suite tests against comprehensive attack vectors:

| Category | Vectors Tested | Description |
|----------|---------------|-------------|
| **XSS** | 13 | Script injection, event handlers, data URIs |
| **SQL Injection** | 10 | Union, blind, time-based, stacked queries |
| **Command Injection** | 10 | Shell metacharacters, command chaining |
| **Path Traversal** | 9 | Directory traversal, symlinks, encodings |
| **Total** | **42** | Comprehensive security validation |

### Security Validation Process

```javascript
// Every benchmark must follow this pattern:
async function runSecurityBenchmark() {
  // 1. Validate security FIRST
  const securityPassed = await validateAllAttackVectors();
  if (!securityPassed) {
    throw new Error('CRITICAL: Security validation failed');
  }
  
  // 2. Measure performance SECOND
  const perfMetrics = await measurePerformance();
  
  // 3. Verify security AGAIN after optimization
  const stillSecure = await validateAllAttackVectors();
  if (!stillSecure) {
    throw new Error('CRITICAL: Optimization broke security');
  }
  
  return perfMetrics;
}
```

### False Negative Testing

**Zero tolerance policy**: Any false negative is a critical failure.

```javascript
// Test for false negatives
const mustBlockAttacks = [
  '../../../etc/passwd',
  "'; DROP TABLE users; --",
  '$(cat /etc/passwd)',
  '<script>alert(1)</script>'
];

for (const attack of mustBlockAttacks) {
  const result = sanitizer.sanitize(attack);
  assert(result.blocked === true, `Failed to block: ${attack}`);
}
```

---

## 📊 Interpreting Benchmark Results

### Performance Indicators

#### 🟢 Healthy Performance
- Consistent response times (low variance)
- Linear scaling with input size
- Predictable memory usage
- No performance cliffs

#### 🟡 Warning Signs
- High variance between runs (>10%)
- Exponential scaling patterns
- Memory growth over time
- Significant GC pauses

#### 🔴 Critical Issues
- False negatives in security tests
- Unbounded memory growth
- Timing attack vulnerabilities
- Performance degradation under attack

### Benchmark Report Format

```
=================================================
MCP Sanitizer Benchmark Report
=================================================
Date: 2025-10-29
Version: Current
Node.js: Current Version
Platform: linux x64

SECURITY VALIDATION
-------------------------------------------------
Attack Vectors Tested: 42
Vectors Blocked: 42 (100%)
False Negatives: 0
False Positive Rate: <0.1%
Status: ✅ SECURE

PERFORMANCE METRICS
-------------------------------------------------
Operation: Input Sanitization
Average Processing: 0.84ms (sub-millisecond)
Max Processing: 2.39ms
Min Processing: 0.28ms
Throughput: 7,500+ ops/sec per core
Memory Usage: <60MB typical, <100MB under attack
CPU Efficiency: Optimized (no artificial delays)

LIBRARY COMPARISON
-------------------------------------------------
escape-html: 31.4M ops/sec (3.6x faster than regex)
sqlstring: 43.3M ops/sec (2.0x faster than custom)
shell-quote: 2.5M ops/sec (industry standard)
unorm: Unicode normalization (NFC/NFD/NFKC/NFKD)

RECOMMENDATIONS
-------------------------------------------------
✅ Security validation passed
✅ Sub-millisecond performance achieved
✅ No memory leaks detected
✅ Production ready
=================================================
```

---

## 🛠️ Creating Custom Benchmarks

### Security Benchmark Template

```javascript
const Benchmark = require('benchmark');
const MCPSanitizer = require('../src/index');

class SecurityBenchmark {
  constructor(name) {
    this.name = name;
    this.sanitizer = new MCPSanitizer('STRICT');
    this.attackVectors = [];
    this.results = [];
  }
  
  // Step 1: Define attack vectors
  addAttackVector(vector, shouldBlock = true) {
    this.attackVectors.push({ vector, shouldBlock });
  }
  
  // Step 2: Validate security
  validateSecurity() {
    for (const { vector, shouldBlock } of this.attackVectors) {
      const result = this.sanitizer.sanitize(vector);
      if (result.blocked !== shouldBlock) {
        throw new Error(`Security validation failed for: ${vector}`);
      }
    }
    return true;
  }
  
  // Step 3: Measure performance
  measurePerformance() {
    const suite = new Benchmark.Suite(this.name);
    
    // Add benchmarks
    suite.add('Benign Input', () => {
      this.sanitizer.sanitize('safe input string');
    });
    
    suite.add('Attack Vector', () => {
      this.sanitizer.sanitize(this.attackVectors[0].vector);
    });
    
    // Run and report
    suite.on('complete', function() {
      console.log('Fastest:', this.filter('fastest').map('name'));
    });
    
    suite.run({ async: true });
  }
  
  // Step 4: Generate report
  report() {
    this.validateSecurity();
    this.measurePerformance();
  }
}

// Usage
const benchmark = new SecurityBenchmark('XSS Protection');
benchmark.addAttackVector('<script>alert(1)</script>', true);
benchmark.addAttackVector('Normal <b>text</b>', false);
benchmark.report();
```

---

## 🎯 Benchmark Best Practices

### Do's ✅

1. **Security First**
   - Always validate security before measuring performance
   - Include real attack vectors in benchmarks
   - Test boundary conditions and edge cases

2. **Realistic Testing**
   - Use real-world input distributions
   - Include both benign and malicious inputs
   - Test with various input sizes

3. **Statistical Rigor**
   - Run sufficient iterations for significance
   - Report percentiles, not just averages
   - Include error margins and confidence intervals

4. **Documentation**
   - Document system specifications
   - Include Node.js and dependency versions
   - Explain what each metric means

### Don'ts ❌

1. **Never Compromise Security**
   - Don't optimize if it reduces security
   - Don't skip attack vector validation
   - Don't ignore false negatives

2. **Avoid Misleading Metrics**
   - Don't cherry-pick best results
   - Don't hide security failures
   - Don't claim 100% protection

3. **Prevent Invalid Comparisons**
   - Don't compare different security levels
   - Don't benchmark without warm-up
   - Don't ignore GC impact

---

## 📚 Additional Resources

### Security Testing
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Benchmark Project](https://owasp.org/www-project-benchmark/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)

### Performance Analysis
- [Node.js Performance Profiling](https://nodejs.org/en/docs/guides/simple-profiling/)
- [V8 Performance Tips](https://v8.dev/docs)
- [Benchmark.js Documentation](https://benchmarkjs.com/)

### Attack Vector References
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

---

## ⚠️ Security Notice

**Remember**: In security libraries, a 10% performance improvement is worthless if it introduces even a 0.01% security vulnerability. 

Always prioritize:
1. **Security** - Must be uncompromised
2. **Performance** - Should be acceptable
3. **Usability** - Can be improved

---

## License

Benchmarks are part of the MCP Sanitizer project under MIT License.