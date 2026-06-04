import { describe, it, expect } from 'vitest';
import { sign as cryptoSign, createPrivateKey } from 'node:crypto';

import { canonicalize, signPayload, verifyPayload } from '../src/crypto/signer.js';
import { generateKeyPair } from '../src/crypto/keypair.js';

// JCS (RFC 8785) canonical serialization for signed bytes.
//
// Every test here exercises the single serializer that both the signer and the
// verifier call. The security property under test is: the same logical value
// always produces the same signed bytes, and anything that could produce
// ambiguous/lossy bytes is refused outright.

describe('JCS canonicalize — key-order independence on sign/verify', () => {
  it('signs with keys in one order and verifies with keys in a different order', () => {
    const { publicKey, privateKey } = generateKeyPair();

    // Keys deliberately out of sorted order, and a nested object likewise.
    const signature = signPayload({ b: 1, a: 2, nested: { y: 9, x: 8 } }, privateKey);

    // Same logical object, every key reordered.
    const result = verifyPayload({ a: 2, nested: { x: 8, y: 9 }, b: 1 }, signature, publicKey);
    expect(result.valid).toBe(true);
  });
});

describe('JCS canonicalize — identical output for semantically identical JSON', () => {
  it('collapses key-order and whitespace differences to the same string', () => {
    const a = JSON.parse('{"a":1,"b":2,"c":[1,2,3]}');
    const b = JSON.parse('{   "c" : [1, 2, 3] ,\n  "b":2,\t"a" : 1 }');

    expect(canonicalize(a)).toBe(canonicalize(b));
    expect(canonicalize(a)).toBe('{"a":1,"b":2,"c":[1,2,3]}');
  });

  it('sorts object keys recursively but never reorders arrays', () => {
    expect(canonicalize({ z: { c: 1, a: 2 }, a: 1 })).toBe('{"a":1,"z":{"a":2,"c":1}}');
    expect(canonicalize([3, 1, 2])).toBe('[3,1,2]');
    expect(canonicalize(['b', 'a'])).toBe('["b","a"]');
  });

  it('sorts by UTF-16 code unit, not locale', () => {
    // 'Z' (0x5A) sorts before 'a' (0x61); 'a' before 'e-acute' (0xE9).
    expect(canonicalize({ 'é': 1, a: 2, Z: 3 })).toBe('{"Z":3,"a":2,"é":1}');
  });
});

describe('JCS canonicalize — refuses values outside the JSON data model', () => {
  it('throws on an undefined object value (never silently dropped)', () => {
    expect(() => canonicalize({ a: 1, b: undefined })).toThrow(/undefined/);
  });

  it('throws on a top-level undefined and on undefined inside an array', () => {
    expect(() => canonicalize(undefined)).toThrow();
    expect(() => canonicalize([1, undefined, 3])).toThrow();
  });

  it('throws on functions, symbols, and bigint', () => {
    expect(() => canonicalize({ f: () => 1 })).toThrow();
    expect(() => canonicalize({ s: Symbol('x') })).toThrow();
    expect(() => canonicalize(10n)).toThrow();
    expect(() => canonicalize({ n: 1n })).toThrow();
  });

  it('throws on NaN / Infinity instead of emitting "null"', () => {
    expect(() => canonicalize(NaN)).toThrow();
    expect(() => canonicalize(Infinity)).toThrow();
    expect(() => canonicalize(-Infinity)).toThrow();
    expect(() => canonicalize({ x: NaN })).toThrow();
  });

  it('throws on a circular reference (object and array forms)', () => {
    const obj: Record<string, unknown> = { a: 1 };
    obj.self = obj;
    expect(() => canonicalize(obj)).toThrow(/circular/i);

    const arr: unknown[] = [1];
    arr.push(arr);
    expect(() => canonicalize(arr)).toThrow(/circular/i);
  });

  it('does NOT throw when the same object appears twice without forming a cycle', () => {
    const shared = { k: 1 };
    expect(() => canonicalize({ a: shared, b: shared })).not.toThrow();
    expect(canonicalize({ a: shared, b: shared })).toBe('{"a":{"k":1},"b":{"k":1}}');
  });
});

describe('JCS canonicalize — number and string serialization (RFC 8785 §3.2.2)', () => {
  it('normalizes -0 to "0"', () => {
    expect(canonicalize(-0)).toBe('0');
    expect(canonicalize({ x: -0 })).toBe('{"x":0}');
  });

  it('escapes control characters and the two mandatory escapes', () => {
    expect(canonicalize(String.fromCharCode(0x00))).toBe('"\\u0000"');
    expect(canonicalize(String.fromCharCode(0x1f))).toBe('"\\u001f"');
    // backspace, tab, newline, form-feed, carriage-return use the short escapes
    expect(canonicalize(String.fromCharCode(8, 9, 10, 12, 13))).toBe('"\\b\\t\\n\\f\\r"');
    expect(canonicalize('a"b\\c')).toBe('"a\\"b\\\\c"');
  });

  it('emits non-ASCII and astral characters literally, not \\u-escaped', () => {
    expect(canonicalize('é')).toBe('"é"');           // e-acute
    expect(canonicalize('\u{1F600}')).toBe('"\u{1F600}"');     // grinning face: valid pair -> literal char
  });

  it('escapes lone surrogates as lowercase \\uXXXX', () => {
    expect(canonicalize('\uD800')).toBe('"\\ud800"'); // lone high surrogate
    expect(canonicalize('\uDC00')).toBe('"\\udc00"'); // lone low surrogate
  });
});

describe('JCS is intentionally NOT backward compatible with non-canonical signatures', () => {
  it('rejects a signature produced over unsorted plain JSON.stringify bytes', () => {
    const { publicKey, privateKey } = generateKeyPair();
    const obj = { b: 1, a: 2 }; // insertion order != sorted order

    // The "old" non-canonical way: sign the raw JSON.stringify bytes, keys NOT sorted.
    const legacyBytes = Buffer.from(JSON.stringify(obj)); // {"b":1,"a":2}
    const legacySig = cryptoSign(null, legacyBytes, createPrivateKey(privateKey)).toString('base64url');

    // Those bytes genuinely differ from the JCS canonical form.
    expect(JSON.stringify(obj)).not.toBe(canonicalize(obj)); // {"b":1,"a":2} vs {"a":2,"b":1}

    // Under JCS verification the legacy signature no longer verifies — by design.
    const result = verifyPayload(obj, legacySig, publicKey);
    expect(result.valid).toBe(false);
  });
});
