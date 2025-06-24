import ece from 'http_ece';

export async function encrypt(userPublicKey, userAuth, payload, contentEncoding) {
  if (!userPublicKey) {
    throw new Error('No user public key provided for encryption.');
  }

  if (typeof userPublicKey !== 'string') {
    throw new Error('The subscription p256dh value must be a string.');
  }

  if (Buffer.from(userPublicKey, 'base64url').length !== 65) {
    throw new Error('The subscription p256dh value should be 65 bytes long.');
  }

  if (!userAuth) {
    throw new Error('No user auth provided for encryption.');
  }

  if (typeof userAuth !== 'string') {
    throw new Error('The subscription auth key must be a string.');
  }

  if (Buffer.from(userAuth, 'base64url').length < 16) {
    throw new Error('The subscription auth key should be at least 16 '
    + 'bytes long');
  }

  if (typeof payload !== 'string' && !Buffer.isBuffer(payload)) {
    throw new Error('Payload must be either a string or a Node Buffer.');
  }

  if (typeof payload === 'string' || payload instanceof String) {
    payload = Buffer.from(payload);
  }

  // Generate ECDH key pair using Web Crypto API
  const keyPair = await (globalThis.crypto || window.crypto).subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    true,
    ['deriveKey', 'deriveBits']
  );
  // Export the public key in uncompressed raw format (04 || X || Y)
  const localPublicKeyRaw = await (globalThis.crypto || window.crypto).subtle.exportKey('raw', keyPair.publicKey);
  const localPublicKey = Buffer.from(new Uint8Array(localPublicKeyRaw)).toString('base64url');

  // Generate 16 random bytes for salt
  const saltArray = new Uint8Array(16);
  (globalThis.crypto || window.crypto).getRandomValues(saltArray);
  const salt = Buffer.from(saltArray).toString('base64url');

  const cipherText = ece.encrypt(payload, {
    version: contentEncoding,
    dh: userPublicKey,
    privateKey: keyPair, // You may need to adapt ece.encrypt to accept CryptoKey
    salt: salt,
    authSecret: userAuth
  });

  return {
    localPublicKey: localPublicKey,
    salt: salt,
    cipherText: cipherText
  };
}
