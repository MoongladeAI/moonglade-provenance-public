/**
 * Cross-engine policy (draft -03 sections 2.1 and 3.3), pinned on the TypeScript side.
 * The Python and Rust engines carry the mirror of these tests; the three must agree.
 */

const { ProvenanceEngine, canonicalizeJson, BINARY_EXTENSIONS, isTextContent } = require('../dist/index.js');

const SAFE = Number.MAX_SAFE_INTEGER;

describe('claims numbers: safe integers only (draft -03 section 3.3)', () => {
  test.each([
    [0, '0'], [1, '1'], [-7, '-7'], [SAFE, '9007199254740991'], [-SAFE, '-9007199254740991'],
    [-0, '0'], [1e2, '100'], [4.0, '4'],
  ])('accepts %p as %s', (n, out) => {
    expect(canonicalizeJson({ x: n })).toBe(`{"x":${out}}`);
  });

  test.each([
    1.5, -0.25, 1e-7, 0.1 + 0.2, SAFE + 1, -SAFE - 1, 2 ** 53, 2 ** 60, 1e21,
    NaN, Infinity, -Infinity,
  ])('rejects %p', (n) => {
    expect(() => canonicalizeJson({ x: n })).toThrow(/integer/i);
    expect(() => canonicalizeJson([n])).toThrow(/integer/i);
    expect(() => canonicalizeJson(n)).toThrow(/integer/i);
  });

  test('the same JSON text gets the same verdict whatever its lexical form', () => {
    expect(canonicalizeJson(JSON.parse('{"a":1.0,"b":1e2,"c":-0}'))).toBe('{"a":1,"b":100,"c":0}');
    expect(() => canonicalizeJson(JSON.parse('{"a":1.5}'))).toThrow();
    expect(() => canonicalizeJson(JSON.parse('{"a":9007199254740992}'))).toThrow();
    expect(() => canonicalizeJson(JSON.parse('{"a":1e400}'))).toThrow(); // parses to Infinity
  });

  test('other rules of section 3.3 still hold', () => {
    expect(canonicalizeJson({ '\u{1F600}': 1, '￿': 2 })).toBe('{"\u{1F600}":1,"￿":2}');
    expect(() => canonicalizeJson({ x: '\ud800' })).toThrow(/surrogate/i);
    expect(() => canonicalizeJson({ '\udc00': 1 })).toThrow(/surrogate/i);
  });

  test('nesting limit is 64 levels', () => {
    let ok = 1;
    for (let i = 0; i < 64; i++) ok = [ok];
    expect(() => canonicalizeJson(ok)).not.toThrow();
    expect(() => canonicalizeJson([ok])).toThrow(/nesting/i);
  });
});

describe('.onnx is a known binary extension (draft -03 section 2.1)', () => {
  test('the extension set names it', () => {
    expect(BINARY_EXTENSIONS.has('onnx')).toBe(true);
  });

  test.each([
    ['CRLF kept', Buffer.from('610d0a62', 'hex')],
    ['leading BOM kept', Buffer.from('efbbbf610d62', 'hex')],
    ['invalid UTF-8 passes through, no error', Buffer.from('61ff62fe00', 'hex')],
    ['no NUL in the sample, high bytes', Buffer.from('c3a9ff0d0a', 'hex')],
  ])('model.onnx: %s', (_n, raw) => {
    expect(isTextContent('model.onnx', raw)).toBe(false);
    expect(ProvenanceEngine.canonicalizeBytes(raw, 'model.onnx').equals(raw)).toBe(true);
    expect(ProvenanceEngine.canonicalizeBytes(raw, 'MODEL.ONNX').equals(raw)).toBe(true);
  });

  test('an unrecognised extension is still sniffed, not assumed binary', () => {
    expect(ProvenanceEngine.canonicalizeBytes(Buffer.from('610d0a62', 'hex'), 'model.onnxx').toString('hex')).toBe('610a62');
  });
});
