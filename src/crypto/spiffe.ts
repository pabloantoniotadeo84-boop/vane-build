export const TRUST_DOMAIN = process.env.SPIFFE_TRUST_DOMAIN ?? 'counsel.local';

export interface ParsedSpiffeId {
  trustDomain: string;
  path: string;
  type: 'agent' | 'company' | 'unknown';
  entityId: string;
}

export function agentSpiffeId(agentId: string): string {
  return `spiffe://${TRUST_DOMAIN}/agent/${encodeURIComponent(agentId)}`;
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
  const entityId = segments[1] ? decodeURIComponent(segments[1]) : path;
  if (kind === 'agent') return { trustDomain, path, type: 'agent', entityId };
  if (kind === 'company') return { trustDomain, path, type: 'company', entityId };
  return { trustDomain, path, type: 'unknown', entityId };
}

export function validateSpiffeId(id: string): boolean {
  return /^spiffe:\/\/[^/]+\/.+$/.test(id);
}
