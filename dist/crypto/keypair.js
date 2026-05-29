import { generateKeyPairSync } from 'node:crypto';
export function generateKeyPair() {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    return { publicKey, privateKey };
}
//# sourceMappingURL=keypair.js.map