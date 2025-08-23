# MCP Sanitizer - Implementation Roadmap

## Quick Wins (1-2 days)

### 1. Add SSRF Protection to URL Validator
**File:** `src/sanitizer/validators/url.js`
```javascript
// Add to URL validator
const SSRF_BLACKLIST = [
  '169.254.169.254', // AWS metadata
  'metadata.google.internal', // GCP metadata
  '::1', // IPv6 localhost
  '::ffff:127.0.0.1', // IPv4-mapped IPv6
];

async validateSSRF(url) {
  const parsed = new URL(url);
  if (SSRF_BLACKLIST.includes(parsed.hostname)) {
    throw new Error('SSRF attempt detected');
  }
  // Add DNS resolution check
  const resolved = await dns.resolve4(parsed.hostname);
  if (this.isPrivateIP(resolved[0])) {
    throw new Error('URL resolves to private IP');
  }
}
```

### 2. Add Simple Rate Limiting
**File:** `src/middleware/rate-limiter.js`
```javascript
class RateLimiter {
  constructor(options = {}) {
    this.requests = new Map();
    this.maxRequests = options.maxRequests || 100;
    this.windowMs = options.windowMs || 60000;
  }

  check(identifier) {
    const now = Date.now();
    const userRequests = this.requests.get(identifier) || [];
    const recentRequests = userRequests.filter(
      time => now - time < this.windowMs
    );
    
    if (recentRequests.length >= this.maxRequests) {
      return false; // Rate limit exceeded
    }
    
    recentRequests.push(now);
    this.requests.set(identifier, recentRequests);
    return true;
  }
}
```

### 3. Add Basic Caching
**File:** `src/utils/cache.js`
```javascript
class SimpleCache {
  constructor(maxSize = 1000, ttl = 300000) {
    this.cache = new Map();
    this.maxSize = maxSize;
    this.ttl = ttl;
  }

  get(key) {
    const item = this.cache.get(key);
    if (!item) return null;
    
    if (Date.now() - item.timestamp > this.ttl) {
      this.cache.delete(key);
      return null;
    }
    
    return item.value;
  }

  set(key, value) {
    if (this.cache.size >= this.maxSize) {
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
    
    this.cache.set(key, {
      value,
      timestamp: Date.now()
    });
  }
}
```

## Medium Priority (3-5 days)

### 4. NoSQL Injection Protection
**File:** `src/sanitizer/validators/nosql.js`
```javascript
class NoSQLValidator {
  constructor(config = {}) {
    this.dangerousOperators = [
      '$where', '$regex', '$ne', '$nin',
      '$exists', '$gte', '$gt', '$lte', '$lt'
    ];
  }

  sanitize(query) {
    if (typeof query !== 'object') return query;
    
    const sanitized = {};
    for (const [key, value] of Object.entries(query)) {
      // Block dangerous operators
      if (this.dangerousOperators.includes(key)) {
        continue; // Skip dangerous operators
      }
      
      // Recursively sanitize nested objects
      if (typeof value === 'object' && value !== null) {
        sanitized[key] = this.sanitize(value);
      } else {
        sanitized[key] = value;
      }
    }
    
    return sanitized;
  }
}
```

### 5. TypeScript Definitions
**File:** `types/index.d.ts`
```typescript
declare module 'mcp-sanitizer' {
  export interface SanitizationOptions {
    policy?: 'STRICT' | 'MODERATE' | 'PERMISSIVE' | 'DEVELOPMENT' | 'PRODUCTION';
    maxStringLength?: number;
    maxDepth?: number;
    allowedProtocols?: string[];
    blockedPatterns?: RegExp[];
  }

  export interface SanitizationResult {
    sanitized: any;
    warnings: Array<{
      type: string;
      message: string;
      severity: 'low' | 'medium' | 'high' | 'critical';
    }>;
    blocked: boolean;
    metadata: {
      processingTime: number;
      originalInput: any;
      context: any;
    };
  }

  export class MCPSanitizer {
    constructor(options?: SanitizationOptions | string);
    sanitize(input: any, context?: any): SanitizationResult;
    sanitizeFilePath(path: string): Promise<string>;
    sanitizeURL(url: string): Promise<string>;
    sanitizeCommand(command: string): Promise<string>;
    sanitizeSQL(query: string): Promise<string>;
    validate(input: any, type: string, options?: any): Promise<any>;
  }

  export function createMiddleware(
    framework: string,
    options?: any
  ): Function;
}
```

### 6. Audit Logger
**File:** `src/utils/audit-logger.js`
```javascript
class AuditLogger {
  constructor(options = {}) {
    this.logLevel = options.logLevel || 'info';
    this.destination = options.destination || console;
    this.includeStack = options.includeStack || false;
  }

  log(event, details) {
    const entry = {
      timestamp: new Date().toISOString(),
      event,
      details,
      level: this.logLevel,
      stack: this.includeStack ? new Error().stack : undefined
    };

    if (this.destination === console) {
      console.log(JSON.stringify(entry));
    } else {
      this.destination.write(JSON.stringify(entry) + '\n');
    }
  }

  security(threat, input, action) {
    this.log('SECURITY_EVENT', {
      threat,
      input: this.sanitizeForLog(input),
      action,
      severity: this.calculateSeverity(threat)
    });
  }

  sanitizeForLog(input) {
    // Remove sensitive data before logging
    if (typeof input === 'string') {
      return input.substring(0, 100) + '...';
    }
    return '[OBJECT]';
  }
}
```

## Advanced Features (1-2 weeks)

### 7. Machine Learning Threat Detection
**File:** `src/ml/threat-detector.js`
```javascript
class MLThreatDetector {
  constructor() {
    this.patterns = [];
    this.threshold = 0.7;
  }

  async train(maliciousInputs, safeInputs) {
    // Extract features from inputs
    const features = this.extractFeatures([
      ...maliciousInputs.map(i => ({ input: i, malicious: true })),
      ...safeInputs.map(i => ({ input: i, malicious: false }))
    ]);
    
    // Train simple classifier
    this.model = this.trainClassifier(features);
  }

  predict(input) {
    const features = this.extractFeatures([{ input }]);
    const score = this.model.predict(features[0]);
    
    return {
      isMalicious: score > this.threshold,
      confidence: score
    };
  }

  extractFeatures(inputs) {
    return inputs.map(({ input }) => ({
      length: input.length,
      specialChars: (input.match(/[^a-zA-Z0-9]/g) || []).length,
      entropy: this.calculateEntropy(input),
      hasSQL: /SELECT|INSERT|UPDATE|DELETE/i.test(input),
      hasScript: /<script|javascript:/i.test(input),
      hasCommand: /[;&|`$()]/g.test(input)
    }));
  }
}
```

### 8. WebAssembly Performance Module
**File:** `src/wasm/sanitizer.wat`
```wat
(module
  (func $sanitize_string (param $ptr i32) (param $len i32) (result i32)
    ;; High-performance string sanitization in WASM
    ;; Implementation here
  )
  (export "sanitize" (func $sanitize_string))
)
```

### 9. GraphQL Query Sanitization
**File:** `src/sanitizer/validators/graphql.js`
```javascript
class GraphQLValidator {
  constructor(config = {}) {
    this.maxDepth = config.maxDepth || 5;
    this.maxComplexity = config.maxComplexity || 100;
  }

  validate(query) {
    const ast = parse(query);
    
    // Check query depth
    const depth = this.calculateDepth(ast);
    if (depth > this.maxDepth) {
      throw new Error('Query too deep');
    }
    
    // Check query complexity
    const complexity = this.calculateComplexity(ast);
    if (complexity > this.maxComplexity) {
      throw new Error('Query too complex');
    }
    
    // Check for introspection in production
    if (this.hasIntrospection(ast) && process.env.NODE_ENV === 'production') {
      throw new Error('Introspection disabled in production');
    }
    
    return { valid: true, depth, complexity };
  }
}
```

## Testing Improvements

### 10. Fuzzing Test Suite
**File:** `test/fuzzing/fuzz.test.js`
```javascript
const crypto = require('crypto');

describe('Fuzzing Tests', () => {
  const sanitizer = new MCPSanitizer('STRICT');
  
  function generateRandomInput(type = 'mixed') {
    const generators = {
      string: () => crypto.randomBytes(Math.random() * 1000).toString('hex'),
      object: () => ({
        [crypto.randomBytes(10).toString('hex')]: generateRandomInput(),
        nested: Math.random() > 0.5 ? generateRandomInput('object') : null
      }),
      array: () => Array(Math.floor(Math.random() * 100))
        .fill(null)
        .map(() => generateRandomInput()),
      mixed: () => {
        const types = ['string', 'object', 'array', 'number', 'boolean', 'null'];
        const type = types[Math.floor(Math.random() * types.length)];
        
        switch(type) {
          case 'number': return Math.random() * Number.MAX_SAFE_INTEGER;
          case 'boolean': return Math.random() > 0.5;
          case 'null': return null;
          default: return generateRandomInput(type);
        }
      }
    };
    
    return generators[type]();
  }
  
  it('should handle 10000 random inputs without crashing', () => {
    for (let i = 0; i < 10000; i++) {
      const input = generateRandomInput();
      
      expect(() => {
        const result = sanitizer.sanitize(input);
        expect(result).toHaveProperty('sanitized');
        expect(result).toHaveProperty('warnings');
        expect(result).toHaveProperty('blocked');
      }).not.toThrow();
    }
  });
});
```

## Performance Monitoring

### 11. Performance Metrics Collection
**File:** `src/monitoring/metrics.js`
```javascript
class PerformanceMonitor {
  constructor() {
    this.metrics = {
      sanitizationTimes: [],
      validationTimes: [],
      cacheHits: 0,
      cacheMisses: 0,
      blockedRequests: 0,
      totalRequests: 0
    };
  }

  recordSanitization(duration) {
    this.metrics.sanitizationTimes.push(duration);
    this.metrics.totalRequests++;
    
    // Keep only last 1000 measurements
    if (this.metrics.sanitizationTimes.length > 1000) {
      this.metrics.sanitizationTimes.shift();
    }
  }

  getStats() {
    const times = this.metrics.sanitizationTimes;
    
    return {
      avg: times.reduce((a, b) => a + b, 0) / times.length,
      p50: this.percentile(times, 50),
      p95: this.percentile(times, 95),
      p99: this.percentile(times, 99),
      cacheHitRate: this.metrics.cacheHits / 
        (this.metrics.cacheHits + this.metrics.cacheMisses),
      blockRate: this.metrics.blockedRequests / this.metrics.totalRequests
    };
  }

  percentile(arr, p) {
    const sorted = [...arr].sort((a, b) => a - b);
    const index = Math.ceil(sorted.length * (p / 100)) - 1;
    return sorted[index];
  }
}
```

## Deployment Considerations

### 12. Docker Support
**File:** `Dockerfile`
```dockerfile
FROM node:18-alpine

# Security: Run as non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

WORKDIR /app

# Copy package files
COPY package*.json ./
RUN npm ci --only=production

# Copy source
COPY --chown=nodejs:nodejs . .

USER nodejs

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('./src/index.js')" || exit 1

EXPOSE 3000

CMD ["node", "src/index.js"]
```

This roadmap provides concrete, implementable improvements that can be tackled incrementally. Each section includes actual code that can be adapted and integrated into the existing codebase.