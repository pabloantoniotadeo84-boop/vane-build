import {
  sign as cryptoSign,
  verify as cryptoVerify,
  createPrivateKey,
  createPublicKey,
} from 'node:crypto';
import type { VerificationResult } from './types.js';

/**
 * JCS — JSON Canonicalization Scheme (RFC 8785).
 *
 * Produces the deterministic UTF-8 string that is signed and, on the other
 * side, re-derived to verify. The signer and EVERY verifier call this exact
 * function on the same logical value, so the canonical bytes can never differ
 * between them — there is no separate "verify-side" serializer to drift out of
 * sync. `Buffer.from(canonicalize(x))` yields the UTF-8 bytes to sign.
 *
 * Guarantees (RFC 8785):
 *   - object keys sorted by UTF-16 code unit, recursively (§3.2.3)
 *   - array element order preserved (never sorted)
 *   - no insignificant whitespace
 *   - strings escaped per §3.2.2.2: \b \t \n \f \r, " and \, other C0 controls
 *     and lone surrogates as lowercase \uXXXX; every other code point literal
 *   - numbers per §3.2.2.3 (ECMAScript Number-to-String); -0 normalized to "0"
 *
 * Refuses (throws) anything outside the JSON data model, so an ambiguous or
 * lossy value can never be signed: undefined, function, symbol, bigint,
 * NaN / ±Infinity, and circular references. This is deliberately stricter than
 * JSON.stringify, which silently maps NaN/Infinity → "null", drops
 * undefined-valued keys, and recurses forever on cycles.
 */
export function canonicalize(value: unknown): string {
  return serializeValue(value, new Set<object>());
}

// `ancestors` is the set of objects/arrays currently on the recursion stack;
// re-encountering one is a cycle.
function serializeValue(value: unknown, ancestors: Set<object>): string {
  if (value === null) return 'null';

  const type = typeof value;
  if (type === 'boolean') return value ? 'true' : 'false';
  if (type === 'number') return serializeNumber(value as number);
  if (type === 'string') return serializeString(value as string);

  if (type === 'object') {
    const obj = value as object;
    if (ancestors.has(obj)) {
      throw new TypeError('canonicalize: circular reference');
    }
    ancestors.add(obj);
    try {
      if (Array.isArray(obj)) {
        // Order is significant for arrays — never sorted.
        return '[' + obj.map((el) => serializeValue(el, ancestors)).join(',') + ']';
      }
      const record = obj as Record<string, unknown>;
      const keys = Object.keys(record).sort(compareCodeUnits);
      const members: string[] = [];
      for (const key of keys) {
        const v = record[key];
        // An undefined-valued key is refused, never silently dropped — dropping
        // would make {a:1,b:undefined} and {a:1} sign to identical bytes.
        if (v === undefined) {
          throw new TypeError(`canonicalize: undefined value at key ${JSON.stringify(key)}`);
        }
        members.push(serializeString(key) + ':' + serializeValue(v, ancestors));
      }
      return '{' + members.join(',') + '}';
    } finally {
      ancestors.delete(obj);
    }
  }

  // undefined, function, symbol, bigint — outside the JSON data model.
  throw new TypeError(`canonicalize: cannot serialize value of type ${type}`);
}

// RFC 8785 §3.2.2.3: numbers use the ECMAScript Number-to-String algorithm,
// which is exactly String(n). It also renders -0 as "0".
function serializeNumber(n: number): string {
  if (!Number.isFinite(n)) {
    // NaN / Infinity / -Infinity have no JSON representation. JSON.stringify
    // turns them into "null" (a silent collision); we refuse instead.
    throw new TypeError(`canonicalize: non-finite number (${String(n)})`);
  }
  return String(n);
}

// RFC 8785 §3.2.2.2 string serialization. Iterates UTF-16 code units so that
// valid surrogate pairs are emitted as their literal (UTF-8) character while
// lone surrogates are escaped.
function serializeString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    switch (code) {
      case 0x08: out += '\\b'; break;
      case 0x09: out += '\\t'; break;
      case 0x0a: out += '\\n'; break;
      case 0x0c: out += '\\f'; break;
      case 0x0d: out += '\\r'; break;
      case 0x22: out += '\\"'; break;   // "
      case 0x5c: out += '\\\\'; break;  // backslash
      default:
        if (code < 0x20) {
          out += '\\u' + code.toString(16).padStart(4, '0');
        } else if (code >= 0xd800 && code <= 0xdbff) {
          // High surrogate: valid only if immediately followed by a low one.
          const next = s.charCodeAt(i + 1);
          if (next >= 0xdc00 && next <= 0xdfff) {
            out += s[i] + s[i + 1]; // valid pair → literal astral character
            i++;
          } else {
            out += '\\u' + code.toString(16).padStart(4, '0'); // lone high surrogate
          }
        } else if (code >= 0xdc00 && code <= 0xdfff) {
          out += '\\u' + code.toString(16).padStart(4, '0'); // lone low surrogate
        } else {
          out += s[i];
        }
    }
  }
  return out + '"';
}

// RFC 8785 §3.2.3 sorts property names by their UTF-16 code units. Spelled out
// explicitly rather than relying on the default sort comparator's coercion.
function compareCodeUnits(a: string, b: string): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const diff = a.charCodeAt(i) - b.charCodeAt(i);
    if (diff !== 0) return diff;
  }
  return a.length - b.length;
}

export function signPayload(payload: unknown, privateKeyPem: string): string {
  const data = Buffer.from(canonicalize(payload));
  const key = createPrivateKey(privateKeyPem);
  // Ed25519: algorithm must be null — it is implied by the key type.
  return cryptoSign(null, data, key).toString('base64url');
}

export function verifyPayload(
  payload: unknown,
  signature: string,
  publicKeyPem: string,
): VerificationResult {
  try {
    const data = Buffer.from(canonicalize(payload));
    const key = createPublicKey(publicKeyPem);
    const sig = Buffer.from(signature, 'base64url');
    const valid = cryptoVerify(null, data, key, sig);
    return { valid };
  } catch (err) {
    return { valid: false, error: (err as Error).message };
  }
}
