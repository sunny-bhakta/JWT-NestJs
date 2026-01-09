#!/usr/bin/env node
const path = require('path');
const fs = require('fs');
const forge = require('node-forge');

const CERT_DIR = path.resolve(__dirname, '..', 'cert');
const SERVER_KEY_PATH = path.join(CERT_DIR, 'server.key');
const SERVER_CERT_PATH = path.join(CERT_DIR, 'server.crt');
const CA_CERT_PATH = path.join(CERT_DIR, 'local-ca.crt');

fs.mkdirSync(CERT_DIR, { recursive: true });

function writeFile(targetPath, data) {
  fs.writeFileSync(targetPath, data, { encoding: 'utf8' });
  console.log(`Generated ${path.relative(process.cwd(), targetPath)}`);
}

function generateCaCertificate() {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 5);

  const attrs = [{ name: 'commonName', value: 'Local Dev CA' }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.publicKey = keys.publicKey;
  cert.setExtensions([
    { name: 'basicConstraints', cA: true },
    { name: 'keyUsage', keyCertSign: true, digitalSignature: true },
    { name: 'subjectKeyIdentifier' },
  ]);

  cert.sign(keys.privateKey, forge.md.sha256.create());
  return { cert, keys };
}

function generateServerCertificate(ca, hostname = 'localhost') {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.serialNumber = '02';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 2);

  cert.publicKey = keys.publicKey;
  cert.setSubject([{ name: 'commonName', value: hostname }]);
  cert.setIssuer(ca.cert.subject.attributes);

  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
    { name: 'extKeyUsage', serverAuth: true },
    {
      name: 'subjectAltName',
      altNames: [
        { type: 2, value: hostname },
        { type: 7, ip: '127.0.0.1' },
      ],
    },
  ]);

  cert.sign(ca.keys.privateKey, forge.md.sha256.create());
  return { cert, keys };
}

function main() {
  const ca = generateCaCertificate();
  const server = generateServerCertificate(ca);

  writeFile(CA_CERT_PATH, forge.pki.certificateToPem(ca.cert));
  writeFile(SERVER_KEY_PATH, forge.pki.privateKeyToPem(server.keys.privateKey));
  writeFile(SERVER_CERT_PATH, forge.pki.certificateToPem(server.cert));
}

main();
