import "reflect-metadata";
import { randomBytes } from "node:crypto";
import net from "node:net";
import tls from "node:tls";
import * as x509 from "@peculiar/x509";

// Node's global WebCrypto (typed with the DOM lib that @peculiar/x509 also uses).
const webcrypto = globalThis.crypto;
x509.cryptoProvider.set(webcrypto);

const ALG = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" } as const;
const DAY_MS = 86_400_000;

export interface CertKeyPem {
  certPem: string;
  keyPem: string;
}

function serial(): string {
  return `01${randomBytes(15).toString("hex")}`;
}

async function exportKeyPem(key: CryptoKey): Promise<string> {
  return x509.PemConverter.encode(await webcrypto.subtle.exportKey("pkcs8", key), "PRIVATE KEY");
}

async function importKeyPem(pem: string): Promise<CryptoKey> {
  const [der] = x509.PemConverter.decode(pem);
  if (!der) throw new Error("ca: invalid private key PEM");
  return webcrypto.subtle.importKey("pkcs8", der, ALG, false, ["sign"]);
}

/** FR-CRY-005: one CA per organization. */
export async function createCa(commonName: string): Promise<CertKeyPem> {
  const keys = await webcrypto.subtle.generateKey(ALG, true, ["sign", "verify"]);
  const now = Date.now();
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: serial(),
    name: `CN=${commonName}`,
    notBefore: new Date(now - 60_000),
    notAfter: new Date(now + 3650 * DAY_MS),
    signingAlgorithm: ALG,
    keys,
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
      await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
    ],
  });
  return { certPem: cert.toString("pem"), keyPem: await exportKeyPem(keys.privateKey) };
}

export async function mintLeaf(ca: CertKeyPem, hostname: string, days = 30): Promise<CertKeyPem> {
  const caCert = new x509.X509Certificate(ca.certPem);
  const signingKey = await importKeyPem(ca.keyPem);
  const keys = await webcrypto.subtle.generateKey(ALG, true, ["sign", "verify"]);
  const now = Date.now();
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: serial(),
    subject: `CN=${hostname}`,
    issuer: caCert.subject,
    notBefore: new Date(now - 60_000),
    notAfter: new Date(now + days * DAY_MS),
    signingAlgorithm: ALG,
    publicKey: keys.publicKey,
    signingKey,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.serverAuth]),
      new x509.SubjectAlternativeNameExtension([
        { type: net.isIP(hostname) ? "ip" : "dns", value: hostname },
      ]),
      await x509.AuthorityKeyIdentifierExtension.create(caCert),
    ],
  });
  return { certPem: cert.toString("pem"), keyPem: await exportKeyPem(keys.privateKey) };
}

/** Per-SNI leaf contexts, minted once per hostname and cached in memory. */
export class LeafCache {
  readonly #ca: CertKeyPem;
  readonly #cache = new Map<string, Promise<tls.SecureContext>>();

  constructor(ca: CertKeyPem) {
    this.#ca = ca;
  }

  context(hostname: string): Promise<tls.SecureContext> {
    const key = hostname.toLowerCase();
    let ctx = this.#cache.get(key);
    if (!ctx) {
      ctx = mintLeaf(this.#ca, key).then((leaf) =>
        tls.createSecureContext({ cert: leaf.certPem, key: leaf.keyPem }),
      );
      ctx.catch(() => this.#cache.delete(key));
      this.#cache.set(key, ctx);
    }
    return ctx;
  }
}
