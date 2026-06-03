export interface ActClaim {
  sub: string;
  act?: ActClaim;
}

export interface DelegationInfo {
  subject: string;
  delegationChain: string[];
  act: ActClaim | null;
  tokenId: string;
}

export interface AttestationRecord {
  index: number;
  timestamp: string;
  payload: unknown;
  delegation?: DelegationInfo;
  hash: string;
  signature: string;
}

export interface ProofNode {
  sibling: string;
  position: 'left' | 'right';
}

export interface InclusionProof {
  record: AttestationRecord;
  proof: ProofNode[];
  root: string;
}

export interface VaneClientOptions {
  baseUrl: string;
  apiKey: string;
}

export class VaneClient {
  private readonly baseUrl: string;
  private readonly apiKey: string;

  constructor(options: VaneClientOptions);
  constructor(baseUrl: string, apiKey: string);
  constructor(baseUrlOrOptions: string | VaneClientOptions, apiKey?: string) {
    if (typeof baseUrlOrOptions === 'object') {
      this.baseUrl = baseUrlOrOptions.baseUrl.replace(/\/$/, '');
      this.apiKey = baseUrlOrOptions.apiKey;
    } else {
      this.baseUrl = baseUrlOrOptions.replace(/\/$/, '');
      this.apiKey = apiKey!;
    }
  }

  async attest(
    agentId: string,
    companyId: string,
    actionType: string,
    payload: unknown,
    delegationToken?: string,
  ): Promise<AttestationRecord> {
    const res = await fetch(`${this.baseUrl}/v1/attest`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify({
        agentId,
        companyId,
        actionType,
        payload,
        ...(delegationToken && { delegation: delegationToken }),
      }),
    });

    if (!res.ok) {
      const body = await res.text();
      throw new Error(`Vane attest failed (${res.status}): ${body}`);
    }

    return res.json() as Promise<AttestationRecord>;
  }

  async getProof(index: number): Promise<InclusionProof> {
    const res = await fetch(`${this.baseUrl}/v1/proof/${index}`, {
      headers: { Authorization: `Bearer ${this.apiKey}` },
    });

    if (!res.ok) {
      const body = await res.text();
      throw new Error(`Vane getProof failed (${res.status}): ${body}`);
    }

    return res.json() as Promise<InclusionProof>;
  }
}
