/**
 * Native Node.js Test Environment for Moonglade Provenance.
 * Replaces Jest entirely using Node 22/24 built-in `node:test` and `node:assert/strict`.
 * Provides zero-dependency, zero-transitive-vulnerability test execution.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

globalThis.describe = test.describe;
globalThis.it = test.it;
globalThis.test = test.it;

// Jest mock compatibility shim using node:test mock
globalThis.jest = {
  spyOn(object, method) {
    const original = object[method];
    let customImpl = null;
    const onceQueue = [];

    const mockFn = function(...args) {
      if (onceQueue.length > 0) {
        const nextImpl = onceQueue.shift();
        return nextImpl.apply(this, args);
      }
      if (customImpl) return customImpl.apply(this, args);
      return original.apply(this, args);
    };

    mockFn.mockImplementation = function(fn) {
      customImpl = fn;
      return mockFn;
    };

    mockFn.mockReturnValue = function(val) {
      customImpl = () => val;
      return mockFn;
    };

    mockFn.mockResolvedValue = function(val) {
      customImpl = async () => val;
      return mockFn;
    };

    mockFn.mockRejectedValue = function(err) {
      customImpl = async () => { throw err; };
      return mockFn;
    };

    mockFn.mockReturnValueOnce = function(val) {
      onceQueue.push(() => val);
      return mockFn;
    };

    mockFn.mockResolvedValueOnce = function(val) {
      onceQueue.push(async () => val);
      return mockFn;
    };

    mockFn.mockRejectedValueOnce = function(err) {
      onceQueue.push(async () => { throw err; });
      return mockFn;
    };

    mockFn.mockRestore = function() {
      object[method] = original;
    };

    object[method] = mockFn;
    globalThis.jest._spies.push(mockFn);
    return mockFn;
  },
  restoreAllMocks() {
    for (const spy of globalThis.jest._spies) {
      if (typeof spy.mockRestore === 'function') spy.mockRestore();
    }
    globalThis.jest._spies = [];
  },
  _spies: []
};

// Table-driven test.each helper
test.it.each = function(table) {
  return function(name, fn) {
    let idx = 0;
    for (const item of table) {
      idx++;
      let rowName;
      if (typeof name === 'function') {
        rowName = name(item);
      } else if (Array.isArray(item)) {
        rowName = name.replace(/%s|%p|%d|%#/g, () => JSON.stringify(item));
      } else if (item && typeof item === 'object') {
        rowName = name.replace('$name', item.name || '').replace('%#', String(idx)).replace('%s', item.name || '');
      } else {
        rowName = name.replace('%p', String(item)).replace('%s', String(item)).replace('%#', String(idx));
      }
      test.it(rowName, async () => {
        // If the test function expects exactly 1 argument and item is an array, pass item directly.
        // If fn expects more arguments, spread it.
        if (Array.isArray(item) && fn.length > 1) await fn(...item);
        else await fn(item);
      });
    }
  };
};

globalThis.describe.each = function(table) {
  return function(name, fn) {
    for (const item of table) {
      const rowName = typeof name === 'function' ? name(item) : name;
      test.describe(rowName, () => {
        if (Array.isArray(item) && fn.length > 1) fn(...item);
        else fn(item);
      });
    }
  };
};

globalThis.beforeAll = test.before;
globalThis.afterAll = test.after;
globalThis.beforeEach = test.beforeEach;
globalThis.afterEach = test.afterEach;

function makeExpect(actual) {
  return {
    toBe(expected) {
      assert.strictEqual(actual, expected);
    },
    toEqual(expected) {
      assert.deepStrictEqual(actual, expected);
    },
    toBeDefined() {
      assert.notStrictEqual(actual, undefined);
    },
    toBeUndefined() {
      assert.strictEqual(actual, undefined);
    },
    toBeNull() {
      assert.strictEqual(actual, null);
    },
    toBeTruthy() {
      assert.ok(actual);
    },
    toBeFalsy() {
      assert.ok(!actual);
    },
    toBeGreaterThan(expected) {
      assert.ok(actual > expected, `${actual} is not > ${expected}`);
    },
    toBeLessThan(expected) {
      assert.ok(actual < expected, `${actual} is not < ${expected}`);
    },
    toBeGreaterThanOrEqual(expected) {
      assert.ok(actual >= expected, `${actual} is not >= ${expected}`);
    },
    toBeLessThanOrEqual(expected) {
      assert.ok(actual <= expected, `${actual} is not <= ${expected}`);
    },
    toContain(expected) {
      if (typeof actual === 'string' || Array.isArray(actual)) {
        assert.ok(actual.includes(expected), `Expected to contain ${expected}`);
      } else if (actual instanceof Set) {
        assert.ok(actual.has(expected), `Set expected to contain ${expected}`);
      } else {
        throw new Error(`Unsupported toContain on ${typeof actual}`);
      }
    },
    toHaveLength(expected) {
      assert.strictEqual(actual.length, expected);
    },
    toMatch(regex) {
      assert.match(String(actual), regex);
    },
    toThrow(expected) {
      assert.throws(actual, expected ? (err) => {
        if (expected instanceof RegExp) return expected.test(err.message || String(err));
        if (typeof expected === 'string') return (err.message || String(err)).includes(expected);
        return true;
      } : undefined);
    },
    get not() {
      return {
        toBe(expected) {
          assert.notStrictEqual(actual, expected);
        },
        toEqual(expected) {
          assert.notDeepStrictEqual(actual, expected);
        },
        toBeNull() {
          assert.notStrictEqual(actual, null);
        },
        toBeUndefined() {
          assert.notStrictEqual(actual, undefined);
        },
        toBeDefined() {
          assert.strictEqual(actual, undefined);
        },
        toContain(expected) {
          if (typeof actual === 'string' || Array.isArray(actual)) {
            assert.ok(!actual.includes(expected), `Expected NOT to contain ${expected}`);
          } else if (actual instanceof Set) {
            assert.ok(!actual.has(expected), `Set expected NOT to contain ${expected}`);
          }
        },
        toThrow(expected) {
          assert.doesNotThrow(actual, expected);
        }
      };
    },
    get rejects() {
      return {
        async toThrow(expected) {
          await assert.rejects(actual, expected ? (err) => {
            if (expected instanceof RegExp) return expected.test(err.message || String(err));
            if (typeof expected === 'string') return (err.message || String(err)).includes(expected);
            return true;
          } : undefined);
        }
      };
    },
    get resolves() {
      return {
        async toBe(expected) {
          const res = await actual;
          assert.strictEqual(res, expected);
        },
        async toEqual(expected) {
          const res = await actual;
          assert.deepStrictEqual(res, expected);
        }
      };
    }
  };
}

globalThis.expect = makeExpect;
