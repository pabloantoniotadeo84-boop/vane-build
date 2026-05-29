import { generateKeyPair, signPayload, verifyPayload, AttestationChain } from './crypto/index.js';
import type { AttestationRecord } from './crypto/index.js';

// ── 1. Key generation ────────────────────────────────────────────────────────

const keys = generateKeyPair();
console.log('── Key pair ────────────────────────────────────────');
console.log(keys.publicKey.trim());

// ── 2. Sign a payload ────────────────────────────────────────────────────────

const action = {
  agentId: 'counsel-agent-001',
  action: 'database.write',
  table: 'transfers',
  rowCount: 1,
  timestamp: new Date().toISOString(),
};

const signature = signPayload(action, keys.privateKey);
console.log('\n── Signed action ───────────────────────────────────');
console.log('signature:', signature);

// ── 3. Verify signature ──────────────────────────────────────────────────────

const good = verifyPayload(action, signature, keys.publicKey);
const tampered = verifyPayload({ ...action, rowCount: 9999 }, signature, keys.publicKey);

console.log('\n── Verification ────────────────────────────────────');
console.log('original  :', good);
console.log('tampered  :', tampered);

// ── 4. Hash-chained attestation log ─────────────────────────────────────────

const chain = new AttestationChain();

chain.append({ agentId: 'counsel-agent-001', action: 'fs.read',  path: '/config/app.yaml' }, keys.privateKey);
chain.append({ agentId: 'counsel-agent-001', action: 'db.query', table: 'users', predicate: 'id=42' }, keys.privateKey);
chain.append({ agentId: 'counsel-agent-002', action: 'http.post', url: 'https://payments.internal/transfer', amount: 100 }, keys.privateKey);

console.log('\n── Chain records ───────────────────────────────────');
for (const rec of chain.getRecords()) {
  console.log(`  [${rec.index}] hash=${rec.hash.slice(0, 16)}…  prev=${rec.previousHash.slice(0, 16)}…`);
  console.log(`       payload=${JSON.stringify(rec.payload)}`);
}

const chainResult = chain.verify(keys.publicKey);
console.log('\n── Chain integrity ─────────────────────────────────');
console.log('valid chain:', chainResult);

// Simulate field-level tampering and re-verify
const records = chain.getRecords() as AttestationRecord[];
const original = records[1];
records[1] = { ...original, payload: { ...original.payload as object, table: 'admin_users' } };

const afterTamper = chain.verify(keys.publicKey);
console.log('after tamper:', afterTamper);
