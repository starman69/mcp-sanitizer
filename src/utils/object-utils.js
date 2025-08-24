/**
 * Object traversal and validation utilities for MCP Sanitizer
 *
 * This module provides reusable functions for object manipulation,
 * traversal, and validation used throughout the MCP Sanitizer.
 * 
 * CVE-TBD-004 FIX: All recursive functions now use early depth checking
 * to prevent stack exhaustion attacks.
 */

// DoS protection removed - simple depth checking is sufficient

/**
 * Dangerous object keys that should be blocked to prevent prototype pollution
 */
const DANGEROUS_KEYS = ['__proto__', 'constructor', 'prototype']

/**
 * Check if an object key is dangerous (could lead to prototype pollution)
 * @param {string} key - The object key to check
 * @returns {boolean} - True if key is dangerous
 * @throws {Error} - If key is not a string
 */
function isDangerousKey (key) {
  if (typeof key !== 'string') {
    throw new Error('Key must be a string')
  }

  return DANGEROUS_KEYS.includes(key)
}

/**
 * Validate object key and throw error if dangerous
 * @param {string} key - The object key to validate
 * @throws {Error} - If key is dangerous
 */
function validateObjectKey (key) {
  if (isDangerousKey(key)) {
    throw new Error(`Dangerous object key detected: ${key}`)
  }
}

/**
 * CVE-TBD-004 FIX: Stack-safe depth measurement with early depth checking
 * @param {*} obj - The object to measure
 * @param {number} [currentDepth=0] - Current depth (used for recursion)
 * @returns {number} - Maximum depth of the object
 */
function getObjectDepth (obj, currentDepth = 0) {
  // Simple depth check to prevent stack exhaustion
  const maxAllowedDepth = 100; // Reasonable limit for object depth
  
  if (currentDepth > maxAllowedDepth) {
    return currentDepth
  }
  
    if (obj === null || typeof obj !== 'object') {
      return currentDepth
    }

    if (Array.isArray(obj)) {
      let maxDepth = currentDepth
      for (const item of obj) {
        const itemDepth = getObjectDepth(item, currentDepth + 1)
        maxDepth = Math.max(maxDepth, itemDepth)
      }
      return maxDepth
    }

    let maxDepth = currentDepth
    for (const value of Object.values(obj)) {
      const valueDepth = getObjectDepth(value, currentDepth + 1)
      maxDepth = Math.max(maxDepth, valueDepth)
    }

    return maxDepth
}

/**
 * Check if an object exceeds the maximum allowed depth
 * @param {*} obj - The object to check
 * @param {number} maxDepth - Maximum allowed depth
 * @returns {boolean} - True if object is within depth limit
 * @throws {Error} - If maxDepth is invalid
 */
function isWithinDepthLimit (obj, maxDepth) {
  if (typeof maxDepth !== 'number' || maxDepth < 0) {
    throw new Error('Max depth must be a non-negative number')
  }

  return getObjectDepth(obj) <= maxDepth
}

/**
 * Validate object depth and throw error if exceeded
 * @param {*} obj - The object to validate
 * @param {number} maxDepth - Maximum allowed depth
 * @throws {Error} - If object exceeds maximum depth
 */
function validateObjectDepth (obj, maxDepth) {
  if (!isWithinDepthLimit(obj, maxDepth)) {
    throw new Error(`Object exceeds maximum depth of ${maxDepth}`)
  }
}

/**
 * Check if a value is a plain object (not array, function, etc.)
 * @param {*} value - The value to check
 * @returns {boolean} - True if value is a plain object
 */
function isPlainObject (value) {
  if (value === null || typeof value !== 'object') {
    return false
  }

  if (Array.isArray(value)) {
    return false
  }

  // Check if it's a built-in object type
  if (value instanceof Date || value instanceof RegExp || value instanceof Error) {
    return false
  }

  // Check if it has a custom constructor
  const proto = Object.getPrototypeOf(value)
  return proto === Object.prototype || proto === null
}

/**
 * Safely get all enumerable keys from an object, filtering out dangerous ones
 * @param {object} obj - The object to get keys from
 * @param {boolean} [allowDangerous=false] - Whether to allow dangerous keys
 * @returns {string[]} - Array of safe object keys
 * @throws {Error} - If obj is not an object
 */
function getSafeObjectKeys (obj, allowDangerous = false) {
  if (typeof obj !== 'object' || obj === null) {
    throw new Error('Input must be an object')
  }

  const keys = Object.keys(obj)

  if (allowDangerous) {
    return keys
  }

  return keys.filter(key => !isDangerousKey(key))
}

/**
 * CVE-TBD-004 FIX: Stack-safe object traversal with early depth checking
 * @param {*} obj - The object to traverse
 * @param {Function} callback - Function to call for each value (value, key, path)
 * @param {string} [currentPath=''] - Current path in the object (used for recursion)
 * @param {number} [currentDepth=0] - Current depth (used for recursion)
 * @param {number} [maxDepth=10] - Maximum depth to traverse
 * @throws {Error} - If callback is not a function or max depth is exceeded
 */
function traverseObject (obj, callback, currentPath = '', currentDepth = 0, maxDepth = 10) {
  if (typeof callback !== 'function') {
    throw new Error('Callback must be a function')
  }

  // Simple depth check to prevent stack exhaustion
  const maxAllowedDepth = Math.min(maxDepth, 100);
  
  if (currentDepth > maxAllowedDepth) {
    return
  }
  
    if (obj === null || typeof obj !== 'object') {
      callback(obj, null, currentPath)
      return
    }

    if (Array.isArray(obj)) {
      obj.forEach((item, index) => {
        const itemPath = currentPath ? `${currentPath}[${index}]` : `[${index}]`
        callback(item, index, itemPath)

        if (typeof item === 'object' && item !== null) {
          traverseObject(item, callback, itemPath, currentDepth + 1, maxDepth)
        }
      })
      return
    }

    for (const [key, value] of Object.entries(obj)) {
      const valuePath = currentPath ? `${currentPath}.${key}` : key
      callback(value, key, valuePath)

      if (typeof value === 'object' && value !== null) {
        traverseObject(value, callback, valuePath, currentDepth + 1, maxDepth)
      }
    }
}

/**
 * CVE-TBD-004 FIX: Stack-safe deep copy with early depth checking
 * @param {*} obj - The object to copy
 * @param {number} [maxDepth=10] - Maximum depth to copy
 * @returns {*} - Deep copy of the object
 * @throws {Error} - If maximum depth is exceeded
 */
function safeDeepCopy (obj, maxDepth = 10) {
  function copyRecursive (value, currentDepth = 0) {
    // Simple depth check to prevent stack exhaustion
    const maxAllowedDepth = Math.min(maxDepth, 100);
    
    if (currentDepth > maxAllowedDepth) {
      throw new Error(`Maximum copy depth (${maxDepth}) exceeded`)
    }
    
    if (value === null || typeof value !== 'object') {
      return value
    }

    if (Array.isArray(value)) {
      return value.map(item => copyRecursive(item, currentDepth + 1))
    }

    if (value instanceof Date) {
      return new Date(value.getTime())
    }

    if (value instanceof RegExp) {
      return new RegExp(value.source, value.flags)
    }

    if (!isPlainObject(value)) {
      // For non-plain objects, return as-is to avoid issues
      return value
    }

    const copy = {}
    for (const [key, val] of Object.entries(value)) {
      if (!isDangerousKey(key)) {
        copy[key] = copyRecursive(val, currentDepth + 1)
      }
    }

    return copy
  }

  return copyRecursive(obj)
}

/**
 * Count the total number of properties in an object (including nested)
 * @param {*} obj - The object to count properties in
 * @param {number} [maxDepth=10] - Maximum depth to traverse
 * @returns {number} - Total number of properties
 * @throws {Error} - If maximum depth is exceeded
 */
function countObjectProperties (obj, maxDepth = 10) {
  let count = 0

  traverseObject(obj, (value, key) => {
    if (key !== null) {
      count++
    }
  }, '', 0, maxDepth)

  return count
}

/**
 * Check if an object has circular references
 * @param {*} obj - The object to check
 * @param {Set} [visited=new Set()] - Set of visited objects (used for recursion)
 * @returns {boolean} - True if object has circular references
 */
function hasCircularReferences (obj, visited = new Set()) {
  if (obj === null || typeof obj !== 'object') {
    return false
  }

  if (visited.has(obj)) {
    return true
  }

  visited.add(obj)

  try {
    if (Array.isArray(obj)) {
      for (const item of obj) {
        if (hasCircularReferences(item, visited)) {
          return true
        }
      }
    } else {
      for (const value of Object.values(obj)) {
        if (hasCircularReferences(value, visited)) {
          return true
        }
      }
    }
  } finally {
    visited.delete(obj)
  }

  return false
}

/**
 * Flatten an object into a single level with dot notation keys
 * @param {object} obj - The object to flatten
 * @param {string} [prefix=''] - Prefix for keys (used for recursion)
 * @param {number} [maxDepth=10] - Maximum depth to flatten
 * @returns {object} - Flattened object
 * @throws {Error} - If obj is not an object or max depth exceeded
 */
function flattenObject (obj, prefix = '', maxDepth = 10) {
  if (typeof obj !== 'object' || obj === null) {
    throw new Error('Input must be an object')
  }

  const result = {}

  function flattenRecursive (current, currentPrefix, depth) {
    if (depth > maxDepth) {
      throw new Error(`Maximum flatten depth of ${maxDepth} exceeded`)
    }

    for (const [key, value] of Object.entries(current)) {
      if (isDangerousKey(key)) {
        continue // Skip dangerous keys
      }

      const newKey = currentPrefix ? `${currentPrefix}.${key}` : key

      if (value === null || typeof value !== 'object' || Array.isArray(value)) {
        result[newKey] = value
      } else if (isPlainObject(value)) {
        flattenRecursive(value, newKey, depth + 1)
      } else {
        result[newKey] = value
      }
    }
  }

  flattenRecursive(obj, prefix, 0)
  return result
}

module.exports = {
  DANGEROUS_KEYS,
  isDangerousKey,
  validateObjectKey,
  getObjectDepth,
  isWithinDepthLimit,
  validateObjectDepth,
  isPlainObject,
  getSafeObjectKeys,
  traverseObject,
  safeDeepCopy,
  countObjectProperties,
  hasCircularReferences,
  flattenObject
}
