import * as ece from "../ece";

export async function encrypt(userPublicKey, userAuth, payload, contentEncoding, senderPublicKeyB64, senderPrivateKeyB64) {
  if (!userPublicKey) {
    throw new Error('No user public key provided for encryption.');
  }

  if (typeof userPublicKey !== 'string') {
    throw new Error('The subscription p256dh value must be a string.');
  }

  const userPublicKeyBytes = Buffer.from(userPublicKey, 'base64url');
  if (userPublicKeyBytes.length !== 65) {
    throw new Error('The subscription p256dh value should be 65 bytes long.');
  }

  if (!userAuth) {
    throw new Error('No user auth provided for encryption.');
  }

  if (typeof userAuth !== 'string') {
    throw new Error('The subscription auth key must be a string.');
  }

  const userAuthBytes = Buffer.from(userAuth, 'base64url');
  if (userAuthBytes.length < 16) {
    throw new Error('The subscription auth key should be at least 16 bytes long');
  }

  if (typeof payload !== 'string' && !Buffer.isBuffer(payload)) {
    throw new Error('Payload must be either a string or a Node Buffer.');
  }

  if (typeof payload === 'string' || payload instanceof String) {
    payload = Buffer.from(payload);
  }

  // Import recipient's public key as CryptoKey
  const importedUserPublicKey = await (globalThis.crypto || window.crypto).subtle.importKey(
    'raw',
    userPublicKeyBytes,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    []
  );

  // Import sender's public key and private key as CryptoKeys (VAPID keys)
  const senderPublicKeyBytes = Buffer.from(senderPublicKeyB64, 'base64url');
  const senderPrivateKeyBytes = Buffer.from(senderPrivateKeyB64, 'base64url');
  const importedSenderPublicKey = await (globalThis.crypto || window.crypto).subtle.importKey(
    'raw',
    senderPublicKeyBytes,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    []
  );
  const importedSenderPrivateKey = await (globalThis.crypto || window.crypto).subtle.importKey(
    'pkcs8',
    senderPrivateKeyBytes,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey', 'deriveBits']
  );

  // Generate 16 random bytes for salt
  const saltArray = new Uint8Array(16);
  (globalThis.crypto || window.crypto).getRandomValues(saltArray);

  // Encrypt using ece with CryptoKey objects and Uint8Array
  const cipherText = await ece.encrypt(payload, {
    version: contentEncoding,
    dh: importedUserPublicKey, // recipient's public key (CryptoKey)
    privateKey: importedSenderPrivateKey, // sender's private key (CryptoKey)
    senderPublicKey: importedSenderPublicKey, // sender's public key (CryptoKey)
    salt: saltArray, // Uint8Array
    authSecret: userAuthBytes // Uint8Array
  });

  return {
    localPublicKey: senderPublicKeyB64,
    salt: Buffer.from(saltArray).toString('base64url'),
    cipherText: cipherText
  };
}
