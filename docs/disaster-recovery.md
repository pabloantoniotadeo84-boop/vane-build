# Vane Disaster Recovery

**RTO (Recovery Time Objective):** 4 hours  
**RPO (Recovery Point Objective):** 1 hour

---

## Scenario 1 — CA Private Key Compromised

A compromised private key means an attacker can forge passports for the affected company. This must be treated as an emergency.

### Immediate response (do this now)

1. **Rotate the key** — call the rotation endpoint as the affected company:
   ```
   POST /v1/companies/rotate-keys
   Authorization: Bearer <company-api-key>
   ```
   The server immediately generates a new Ed25519 keypair, retires the old key, and all new passports are signed with the new key. The old key enters a 24-hour grace period during which it can still *verify* passports but cannot issue new ones.

2. **Shorten the grace period** — restart the server with `VANE_KEY_ROTATION_GRACE_PERIOD_HOURS=0` (or a very small value such as `0.083` for 5 minutes) to close the window during which the compromised key's signatures are still accepted.

3. **Revoke in-flight passports** — enumerate any passports you know were issued with the compromised key and revoke their JTIs via:
   ```
   POST /v1/passports/{jti}/revoke
   Authorization: Bearer <company-api-key>
   {"reason": "key-compromise"}
   ```
   Because passports have a maximum TTL of 1 hour, all compromised passports expire within 1 hour of issuance even without explicit revocation.

4. **Notify downstream verifiers** — push the updated public-key set. Verifiers should re-fetch:
   ```
   GET /v1/ca/public-keys?companyId=<id>
   ```
   This returns the new active key. Verifiers that cached the old key must drop it.

5. **Rotate the company API key** — if the attacker could have obtained your API key alongside the CA private key:
   ```
   POST /v1/keys
   Authorization: Bearer <company-api-key>
   {"label": "post-incident"}
   ```
   Then delete the old key:
   ```
   DELETE /v1/keys/<old-key>
   ```

6. **Audit the attestation chain** — call `GET /v1/verify` to confirm chain integrity and identify any forged records inserted during the compromise window.

### Why this works

Vane uses short-lived passports (5 minutes to 1 hour) as the primary security control. Even if an attacker holds the private key, they can only forge passports whose expiry is within the maximum TTL. After 1 hour all forged passports expire. The key rotation endpoint reduces the window for future forgeries to zero immediately.

---

## Scenario 2 — Railway Database Goes Down

The PostgreSQL database on Railway is Vane's only persistence layer. If it becomes unavailable:

- **New attestations fail.** `POST /v1/attest` will return 500 — the server cannot write new records.
- **New passports can still be issued** if the company's keypair was loaded into memory before the outage (in-memory tenant state is populated at startup).
- **Existing passports remain verifiable offline.** Any party that holds the CA public key (fetched from `GET /v1/ca/public-key` before the outage) can verify any in-window passport without contacting Vane's servers. `verifyPassport` makes no network calls.
- **The server enters a de-facto read-only mode** — writes fail; reads from in-memory state succeed.

### Mitigation

1. Railway Postgres has automatic failover for paid plans. The typical downtime for a failover is under 60 seconds.
2. Enable Railway's point-in-time recovery. The RPO is 1 hour, matching Vane's maximum passport TTL — in the worst case you lose 1 hour of attestation records.
3. If the database is down and attestations are mission-critical, pre-warm a read replica and promote it manually via Railway's dashboard.

---

## Scenario 3 — Vane Goes Bankrupt or Shuts Down

Passports are self-contained signed JWTs. Vane's servers are **not required to verify them**.

- Any party that holds the company's CA public key can verify passports offline forever — until the passport's `exp` claim passes.
- The maximum passport TTL is 1 hour (`PASSPORT_TTL_MAX = 3600`). At shutdown, the worst-case exposure is 1 hour of unverifiable new passports (no server to issue them), but existing in-window passports continue to verify against the cached public key.
- The attestation chain (stored in PostgreSQL) is tamper-evident. If you export the chain before shutdown via `GET /v1/chain`, anyone with the CA public key can independently verify every record via the Merkle tree.

### What companies should do before relying on Vane in production

1. **Export and cache the CA public key** at startup. Fetch `GET /v1/ca/public-key?companyId=<id>` and store the PEM locally. This is the only artifact needed for offline verification.
2. **Export the attestation chain periodically.** `GET /v1/chain` returns the complete, verifiable log. Store it in your own durable storage.
3. **Pin the `verifyPassport` implementation.** The mcp-middleware's `verify.ts` has zero external dependencies — copy it to your own codebase so verification never depends on a Vane-hosted package.

---

## Key Custody

### At rest

Private keys are stored in the `keys` table as PKCS8 PEM strings. If `VANE_MASTER_KEY` is set, each private key is encrypted with AES-256-GCM before being written to the database:

```
enc:v1:<iv_hex>:<tag_hex>:<ciphertext_hex>
```

If the environment variable is absent, keys are stored in plaintext and the server logs a warning at startup.

### In production

- Store `VANE_MASTER_KEY` in a secrets manager (AWS Secrets Manager, HashiCorp Vault, Railway's secret injection, etc.) — **not** as a plain environment variable in a `.env` file or in your CI config.
- The master key should be a high-entropy random string (≥ 32 bytes). Derive it from your secrets manager at process startup; never write it to disk.
- Rotate the master key periodically by: (1) fetching and decrypting all private keys with the old master key, (2) setting the new `VANE_MASTER_KEY`, (3) re-saving all keys (which will re-encrypt under the new key).

### Key rotation schedule

Rotate company CA keypairs on a regular schedule (recommended: every 90 days) in addition to rotating on suspicion of compromise. Use the `POST /v1/companies/rotate-keys` endpoint. The grace period (`VANE_KEY_ROTATION_GRACE_PERIOD_HOURS`, default 24) ensures all in-flight passports continue to verify during the transition.

---

## Backup Procedure

1. **Railway automatic backups** — Railway Postgres (Pro plan) runs continuous WAL-based backups with 7-day retention and point-in-time recovery (PITR) to any second within that window.
2. **Daily logical dumps** — run a daily `pg_dump` of the Vane database and upload to an external store (S3, GCS, Backblaze). The dump should be encrypted at rest.
3. **Restore procedure:**
   - Provision a new Railway Postgres instance.
   - Restore from PITR or logical dump: `psql $DATABASE_URL < vane-backup.sql`.
   - Restart the Vane server — `store.init()` is idempotent and will create any missing tables.
   - Verify chain integrity: `GET /v1/verify` for each company.

### RPO calculation

| Event | Data loss |
|---|---|
| Railway PITR failover | < 5 seconds |
| Daily logical dump restore | Up to 24 hours of attestation records |
| Manual PITR restore | Up to 1 hour (matching `PASSPORT_TTL_MAX`) |

The target RPO is **1 hour**, achievable via Railway PITR.

---

## RTO Breakdown

| Step | Estimated time |
|---|---|
| Detect outage and page on-call | 15 min |
| Provision new Railway Postgres instance | 5 min |
| Restore from PITR or dump | 30 min |
| Restart Vane server + hydrate tenants | 5 min |
| Smoke-test all endpoints | 15 min |
| **Total** | **~70 min** |

Target RTO is **4 hours**, giving comfortable margin for worst-case scenarios (manual restore from a daily dump, key re-encryption, verifier cache invalidation).
