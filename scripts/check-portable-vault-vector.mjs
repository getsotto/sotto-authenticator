import assert from 'node:assert/strict';
import { createDecipheriv, hkdfSync } from 'node:crypto';
import { readFileSync } from 'node:fs';

// This check opens one public synthetic vector using Node's crypto primitives.
const fixturePath = new URL(
  '../crates/authenticator-bridge/src/portable_vault/fixtures/populated-vault.json',
  import.meta.url,
);
const { entropyHex, plaintext, envelopeHex } = JSON.parse(readFileSync(fixturePath, 'utf8'));
assert.match(entropyHex, /^[0-9a-f]{64}$/);
assert.match(envelopeHex, /^(?:[0-9a-f]{2})+$/);
const entropy = Buffer.from(entropyHex, 'hex');
const envelope = Buffer.from(envelopeHex, 'hex');
assert.ok(envelope.length >= 128, 'incomplete fixture envelope');
assert.equal(envelope.subarray(0, 8).toString('hex'), '534f545601010000');

function decrypt(key, nonce, sealed, associatedData) {
  const tagLength = 16;
  const decipher = createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: tagLength });
  decipher.setAAD(associatedData);
  decipher.setAuthTag(sealed.subarray(-tagLength));
  return Buffer.concat([decipher.update(sealed.subarray(0, -tagLength)), decipher.final()]);
}

const salt = envelope.subarray(8, 40);
const context = 'org.getsotto.sotto-authenticator/portable-vault/v1/kek';
const wrappingKey = Buffer.from(hkdfSync('sha256', entropy, salt, context, 32));
const dataKey = decrypt(
  wrappingKey,
  envelope.subarray(40, 52),
  envelope.subarray(52, 100),
  envelope.subarray(0, 40),
);
const decoded = decrypt(
  dataKey,
  envelope.subarray(100, 112),
  envelope.subarray(112),
  envelope.subarray(0, 100),
);
assert.deepEqual(decoded, Buffer.from(plaintext, 'utf8'));
console.log('Populated vault fixture authenticated and matched the expected bytes.');
