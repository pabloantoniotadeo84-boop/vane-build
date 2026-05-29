import { sign as cryptoSign, verify as cryptoVerify, createPrivateKey, createPublicKey, } from 'node:crypto';
/**
 * Deterministic JSON serialization: keys sorted recursively.
 * Accepts any JSON-serializable value; undefined/Symbol/function are not supported.
 */
export function canonicalize(value) {
    if (value === null || typeof value !== 'object')
        return JSON.stringify(value);
    if (Array.isArray(value))
        return `[${value.map(canonicalize).join(',')}]`;
    const obj = value;
    const pairs = Object.keys(obj)
        .sort()
        .map(k => `${JSON.stringify(k)}:${canonicalize(obj[k])}`);
    return `{${pairs.join(',')}}`;
}
export function signPayload(payload, privateKeyPem) {
    const data = Buffer.from(canonicalize(payload));
    const key = createPrivateKey(privateKeyPem);
    // Ed25519: algorithm must be null — it is implied by the key type.
    return cryptoSign(null, data, key).toString('base64url');
}
export function verifyPayload(payload, signature, publicKeyPem) {
    try {
        const data = Buffer.from(canonicalize(payload));
        const key = createPublicKey(publicKeyPem);
        const sig = Buffer.from(signature, 'base64url');
        const valid = cryptoVerify(null, data, key, sig);
        return { valid };
    }
    catch (err) {
        return { valid: false, error: err.message };
    }
}
//# sourceMappingURL=signer.js.map