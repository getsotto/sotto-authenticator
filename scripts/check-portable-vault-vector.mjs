import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, createHash, hkdfSync } from 'node:crypto';
import { readFileSync } from 'node:fs';

// Fixed inputs belong to this public synthetic vector.
const fixturePath = new URL(
  '../crates/authenticator-bridge/src/portable_vault/fixtures/populated-vault.json',
  import.meta.url,
);
const { entropyHex, plaintext, envelopeHex, replacementWrappingRecordHex, fixedInputs, sizeLimit } =
  JSON.parse(readFileSync(fixturePath, 'utf8'));
assert.match(entropyHex, /^[0-9a-f]{64}$/);
assert.match(envelopeHex, /^(?:[0-9a-f]{2})+$/);
assert.match(replacementWrappingRecordHex, /^[0-9a-f]{120}$/);
const entropy = Buffer.from(entropyHex, 'hex');
const envelope = Buffer.from(envelopeHex, 'hex');
const header = Buffer.from('534f545601010000', 'hex');
assert.ok(envelope.length >= 128, 'incomplete fixture envelope');
assert.deepEqual(envelope.subarray(0, 8), header);

function encrypt(key, nonce, message, associatedData) {
  const cipher = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
  cipher.setAAD(associatedData);
  return Buffer.concat([cipher.update(message), cipher.final(), cipher.getAuthTag()]);
}

function decrypt(key, nonce, sealed, associatedData) {
  const tagLength = 16;
  const decipher = createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: tagLength });
  decipher.setAAD(associatedData);
  decipher.setAuthTag(sealed.subarray(-tagLength));
  return Buffer.concat([decipher.update(sealed.subarray(0, -tagLength)), decipher.final()]);
}

function deriveWrappingKey(salt) {
  const context = 'org.getsotto.sotto-authenticator/portable-vault/v1/kek';
  return Buffer.from(hkdfSync('sha256', entropy, salt, context, 32));
}

function unwrapDataKey(bytes) {
  const wrappingKey = deriveWrappingKey(bytes.subarray(8, 40));
  return decrypt(wrappingKey, bytes.subarray(40, 52), bytes.subarray(52, 100), bytes.subarray(0, 40));
}

function openPayload(key, bytes) {
  return decrypt(key, bytes.subarray(100, 112), bytes.subarray(112), bytes.subarray(0, 100));
}

const dataKey = unwrapDataKey(envelope);
const message = Buffer.from(plaintext, 'utf8');
const decoded = openPayload(dataKey, envelope);
assert.deepEqual(decoded, message);
console.log('Populated vault fixture authenticated and matched the expected bytes.');

function sealFixture(message, inputs) {
  const salt = Buffer.alloc(32, inputs.saltByte);
  const wrappingNonce = Buffer.alloc(12, inputs.wrappingNonceByte);
  const dataKey = Buffer.alloc(32, inputs.dataKeyByte);
  const payloadNonce = Buffer.alloc(12, inputs.payloadNonceByte);
  const wrappingData = Buffer.concat([header, salt]);
  const wrapped = encrypt(deriveWrappingKey(salt), wrappingNonce, dataKey, wrappingData);
  const payloadData = Buffer.concat([wrappingData, wrappingNonce, wrapped]);
  const sealed = encrypt(dataKey, payloadNonce, message, payloadData);
  return Buffer.concat([payloadData, payloadNonce, sealed]);
}

assert.deepEqual(sealFixture(message, fixedInputs), envelope);
console.log('Independent sealing reproduced the populated envelope byte for byte.');

const replaced = Buffer.from(envelope);
Buffer.from(replacementWrappingRecordHex, 'hex').copy(replaced, 40);
const rewrappedDataKey = unwrapDataKey(replaced);
assert.deepEqual(rewrappedDataKey, dataKey);
assert.throws(() => openPayload(rewrappedDataKey, replaced), /unable to authenticate/i);
console.log('Payload authentication rejected the substituted wrapping record.');

assert.equal(sizeLimit.plaintextBytes, 1024 * 1024);
const padded = Buffer.alloc(sizeLimit.plaintextBytes, 0x20);
assert.ok(message.length < padded.length);
message.copy(padded);
const maximumEnvelope = sealFixture(padded, sizeLimit.fixedInputs);
assert.equal(maximumEnvelope.length, padded.length + 128);
assert.equal(createHash('sha256').update(maximumEnvelope).digest('hex'), sizeLimit.envelopeSha256);
assert.deepEqual(openPayload(unwrapDataKey(maximumEnvelope), maximumEnvelope), padded);
console.log('Exact-limit envelope authenticated and matched the expected digest.');
