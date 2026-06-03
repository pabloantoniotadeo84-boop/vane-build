export const TRUST_DOMAIN = process.env.SPIFFE_TRUST_DOMAIN ?? 'vane.local';

export interface ParsedSpiffeId {
  trustDomain: string;
  path: string;
  type: 'agent' | 'company' | 'unknown';
  entityId: string;
}

// In multi-tenant deployments agents are namespaced under their company:
//   spiffe://vane.local/company/{companyId}/agent/{agentId}
// This guarantees global uniqueness across tenants within the trust domain.
export function agentSpiffeId(companyId: string, agentId: string): string {
  return `spiffe://${TRUST_DOMAIN}/company/${encodeURIComponent(companyId)}/agent/${encodeURIComponent(agentId)}`;
}

export function companySpiffeId(companyId: string): string {
  return `spiffe://${TRUST_DOMAIN}/company/${encodeURIComponent(companyId)}`;
}

export function parseSpiffeId(id: string): ParsedSpiffeId | null {
  const match = id.match(/^spiffe:\/\/([^/]+)\/(.+)$/);
  if (!match) return null;
  const trustDomain = match[1];
  const path = match[2];
  const segments = path.split('/');
  const kind = segments[0];

  if (kind === 'company') {
    const companyId = segments[1] ? decodeURIComponent(segments[1]) : path;
    if (segments[2] === 'agent' && segments[3]) {
      return { trustDomain, path, type: 'agent', entityId: decodeURIComponent(segments[3]) };
    }
    return { trustDomain, path, type: 'company', entityId: companyId };
  }

  return { trustDomain, path, type: 'unknown', entityId: path };
}

export function validateSpiffeId(id: string): boolean {
  return /^spiffe:\/\/[^/]+\/.+$/.test(id);
}
