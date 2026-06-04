#!/usr/bin/env -S npx tsx
/**
 * Offline Vane inclusion-proof verifier.
 *
 *   tsx scripts/verify-proof.ts <proof.json> <ca-public-key.pem>
 *   tsx scripts/verify-proof.ts <proof.json> --ca-from-proof
 *
 * Reads an inclusion-proof JSON (the body of
 * GET /v1/agents/:agentId/attestations/:index/proof) and a CA public key, and
 * reports whether the proof is valid. It makes NO network calls and touches NO
 * database — verification is pure crypto over the supplied JSON.
 *
 * A third-party auditor pins the CA public key out of band and passes it as the
 * second argument. `--ca-from-proof` instead trusts the key embedded in the
 * proof and is for local demos only (it proves the proof is internally
 * consistent, not that it came from the real CA).
 *
 * Exit codes:  0 = valid   1 = invalid   2 = usage / IO / parse error
 */
import { readFileSync, existsSync } from 'node:fs';
import { verifyInclusionProof, type InclusionProofResponse } from '../src/crypto/inclusion.js';

function usage(message?: string): never {
  if (message) console.error(`error: ${message}\n`);
  console.error('Usage:');
  console.error('  tsx scripts/verify-proof.ts <proof.json> <ca-public-key.pem>');
  console.error('  tsx scripts/verify-proof.ts <proof.json> --ca-from-proof');
  console.error('');
  console.error('Verifies a Vane inclusion proof offline. Exit 0 = valid, 1 = invalid.');
  process.exit(2);
}

const [, , proofPath, caArg] = process.argv;
if (!proofPath || !caArg) usage('two arguments are required');

// ── Load the proof JSON ─────────────────────────────────────────────────────────
if (!existsSync(proofPath)) usage(`proof file not found: ${proofPath}`);
let proof: InclusionProofResponse;
try {
  proof = JSON.parse(readFileSync(proofPath, 'utf8')) as InclusionProofResponse;
} catch (err) {
  usage(`could not parse proof JSON: ${(err as Error).message}`);
}

// ── Resolve the CA public key ────────────────────────────────────────────────────
let caPublicKey: string;
let caSource: string;
if (caArg === '--ca-from-proof') {
  if (typeof proof.caPublicKey !== 'string' || !proof.caPublicKey) {
    usage('proof has no embedded caPublicKey to use with --ca-from-proof');
  }
  caPublicKey = proof.caPublicKey;
  caSource = 'embedded in proof (NOT independently pinned)';
} else if (existsSync(caArg)) {
  caPublicKey = readFileSync(caArg, 'utf8');
  caSource = caArg;
} else if (caArg.includes('BEGIN PUBLIC KEY')) {
  caPublicKey = caArg;
  caSource = 'inline PEM argument';
} else {
  usage(`CA public key not found (not a file, not inline PEM): ${caArg}`);
}

// ── Verify ───────────────────────────────────────────────────────────────────────
const result = verifyInclusionProof(proof, caPublicKey);

console.log('Vane inclusion-proof verification');
console.log('─'.repeat(50));
console.log(`proof file   : ${proofPath}`);
console.log(`CA key       : ${caSource}`);
if (proof && typeof proof === 'object') {
  console.log(`company      : ${proof.companyId ?? '(none)'}`);
  console.log(`agent        : ${proof.agentId ?? '(none)'}`);
  console.log(`record index : ${proof.index ?? '(none)'}`);
  console.log(`tree size    : ${proof.treeSize ?? '(none)'}`);
  console.log(`root         : ${proof.root ?? '(none)'}`);
}
console.log('─'.repeat(50));

if (result.valid) {
  console.log('RESULT: ✅ VALID');
  console.log(`Record #${result.index} is included in the CA-signed tree of size ${result.treeSize}.`);
  process.exit(0);
} else {
  console.log('RESULT: ❌ INVALID');
  console.log(`Reason: ${result.reason}`);
  process.exit(1);
}
