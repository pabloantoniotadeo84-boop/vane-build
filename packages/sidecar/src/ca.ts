import * as x509 from '@peculiar/x509';
import { webcrypto } from 'node:crypto';

// Wire @peculiar/x509 to Node's native WebCrypto (available since Node 15+)
x509.cryptoProvider.set(webcrypto as unknown as Crypto);

export interface MitmCA {
  /** PEM-encoded root CA certificate. Agents must add this to their trust store. */
  certPem: string;
  /** @internal used to sign leaf certificates */
  _cert: x509.X509Certificate;
  /** @internal private key for signing */
  _signingKey: CryptoKey;
}

export interface LeafCert {
  certPem: string;
  keyPem: string;
}

// Cache leaf certs by hostname — regenerating a key pair per-connection is wasteful.
// Each entry is valid for 1 hour; certs themselves are valid for 24 hours.
const certCache = new Map<string, { leaf: LeafCert; expiresAt: number }>();

export async function createMitmCA(): Promise<MitmCA> {
  const keys = await webcrypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  ) as CryptoKeyPair;

  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: 'CN=Counsel MITM CA,O=Counsel',
    notBefore: new Date(),
    notAfter: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    keys,
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
        true,
      ),
      await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
    ],
  });

  return {
    certPem: cert.toString('pem'),
    _cert: cert,
    _signingKey: keys.privateKey,
  };
}

/**
 * Returns a leaf TLS certificate for the given hostname, signed by the MITM CA.
 * Results are cached for 1 hour per hostname (certs are valid for 24 hours).
 */
export async function getCert(ca: MitmCA, hostname: string): Promise<LeafCert> {
  const cached = certCache.get(hostname);
  if (cached && cached.expiresAt > Date.now() + 60_000) {
    return cached.leaf;
  }
  const leaf = await issueCert(ca, hostname);
  certCache.set(hostname, { leaf, expiresAt: Date.now() + 3_600_000 });
  return leaf;
}

async function issueCert(ca: MitmCA, hostname: string): Promise<LeafCert> {
  const keys = await webcrypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  ) as CryptoKeyPair;

  const serial = Buffer.from(webcrypto.getRandomValues(new Uint8Array(8))).toString('hex');
  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);

  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: serial,
    subject: `CN=${hostname}`,
    issuer: ca._cert.subject,
    notBefore: new Date(),
    notAfter: new Date(Date.now() + 24 * 60 * 60 * 1000),
    signingKey: ca._signingKey,
    publicKey: keys.publicKey,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    extensions: [
      new x509.BasicConstraintsExtension(false),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment,
      ),
      new x509.ExtendedKeyUsageExtension(['1.3.6.1.5.5.7.3.1']), // serverAuth
      new x509.SubjectAlternativeNameExtension([
        isIp ? { type: 'ip', value: hostname } : { type: 'dns', value: hostname },
      ]),
      await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
      await x509.AuthorityKeyIdentifierExtension.create(ca._cert),
    ],
  });

  const keyDer = await webcrypto.subtle.exportKey('pkcs8', keys.privateKey);
  const keyB64 = Buffer.from(keyDer).toString('base64');
  const keyPem = [
    '-----BEGIN PRIVATE KEY-----',
    ...keyB64.match(/.{1,64}/g)!,
    '-----END PRIVATE KEY-----',
    '',
  ].join('\n');

  return { certPem: cert.toString('pem'), keyPem };
}
