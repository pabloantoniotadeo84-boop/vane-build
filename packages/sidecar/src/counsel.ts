import { verify as cryptoVerify, createPublicKey } from 'node:crypto';

export interface SidecarConfig {
  apiUrl: string;
  apiKey: string;
  agentId: string;
  companyId: string;
}

interface PassportIssuanceResponse {
  passport: string;
  caPublicKey: string;
  expiresIn: number;
  agentId: string;
  spiffeId: string;
}

export class CounselClient {
  private readonly cfg: SidecarConfig;

  private passport: string | null = null;
  private caPublicKey: string | null = null;
  // Unix seconds when the cached passport expires
  private passportExp = 0;

  constructor(cfg: SidecarConfig) {
    this.cfg = { ...cfg, apiUrl: cfg.apiUrl.replace(/\/$/, '') };
  }

  /** Fetch the initial passport. Must be called once before the proxy starts. */
  async initialize(): Promise<void> {
    await this.refreshPassport();
    console.log(
      `[counsel-sidecar] Initialized — agent=${this.cfg.agentId} company=${this.cfg.companyId}`,
    );
  }

  /** Returns the cached passport, refreshing it when fewer than 5 minutes remain. */
  async getPassport(): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    if (!this.passport || this.passportExp - now < 300) {
      await this.refreshPassport();
    }
    return this.passport!;
  }

  getCaPublicKey(): string | null {
    return this.caPublicKey;
  }

  private async refreshPassport(): Promise<void> {
    const res = await fetch(
      `${this.cfg.apiUrl}/v1/agents/${encodeURIComponent(this.cfg.agentId)}/passport`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this.cfg.apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ scopes: ['tool:*', 'attest:write'] }),
      },
    );

    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw new Error(
        `Counsel passport issuance failed: HTTP ${res.status} — ${body}`,
      );
    }

    const data = (await res.json()) as PassportIssuanceResponse;
    this.passport = data.passport;
    this.caPublicKey = data.caPublicKey;
    this.passportExp = Math.floor(Date.now() / 1000) + data.expiresIn;
  }

  /**
   * Records an outbound HTTP call in the Counsel attestation chain.
   * Fire-and-forget — never blocks the proxied request.
   */
  attest(method: string, url: string, extra?: Record<string, unknown>): void {
    fetch(`${this.cfg.apiUrl}/v1/attest`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.cfg.apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        agentId: this.cfg.agentId,
        actionType: 'outbound-http',
        payload: { method, url, ...extra },
      }),
    }).catch((err: unknown) => {
      console.error('[counsel-sidecar] Attestation failed (non-fatal):', err);
    });
  }

  /**
   * Verifies a Counsel Agent Passport (CAP+JWT) locally using the cached CA
   * public key. Does NOT check revocation — for revocation checking, query
   * the Counsel OCSP endpoint (GET /v1/ocsp/:jti).
   *
   * Checks: EdDSA signature, typ=CAP+JWT, exp, aud=counsel:passport:v1.
   */
  verifyPassportLocal(token: string): boolean {
    if (!this.caPublicKey) return false;

    const parts = token.split('.');
    if (parts.length !== 3) return false;
    const [headerB64, payloadB64, sigB64] = parts;

    try {
      const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf8')) as Record<string, unknown>;
      if (header['alg'] !== 'EdDSA' || header['typ'] !== 'CAP+JWT') return false;

      const valid = cryptoVerify(
        null,
        Buffer.from(`${headerB64}.${payloadB64}`),
        createPublicKey(this.caPublicKey),
        Buffer.from(sigB64, 'base64url'),
      );
      if (!valid) return false;

      const claims = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8')) as Record<string, unknown>;
      const now = Math.floor(Date.now() / 1000);
      if (typeof claims['exp'] !== 'number' || claims['exp'] < now) return false;
      if (!Array.isArray(claims['aud']) || !(claims['aud'] as string[]).includes('counsel:passport:v1')) return false;

      return true;
    } catch {
      return false;
    }
  }
}
