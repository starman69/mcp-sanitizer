/**
 * Shared helpers for the framework middleware.
 */

/**
 * The value a middleware should hand on for one sanitized request part.
 * A blocked part is withheld (empty, same shape) so the raw input never reaches
 * the handler, even in `mode: 'sanitize'`.
 * @param {Object} result - `MCPSanitizer#sanitize` result
 * @param {*} original - The unsanitized value
 * @returns {*} - `result.sanitized`, or an empty object/array/null when blocked
 */
function sanitizedOrWithheld (result, original) {
  if (!result.blocked) return result.sanitized;
  if (Array.isArray(original)) return [];
  return original !== null && typeof original === 'object' ? {} : null;
}

/**
 * Set a request property, including getter-only ones such as Express 5 `req.query`,
 * where a plain assignment is silently ignored outside strict mode.
 * @param {Object} target - Request object
 * @param {string} key - Property name
 * @param {*} value - New value
 */
function setRequestProperty (target, key, value) {
  Object.defineProperty(target, key, { value, writable: true, configurable: true, enumerable: true });
}

module.exports = { sanitizedOrWithheld, setRequestProperty };
