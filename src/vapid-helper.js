import asn1 from 'asn1.js';
import { SignJWT } from 'jose';
import { URL } from 'url';

import WebPushConstants from './web-push-constants.js';
import * as urlBase64Helper from './urlsafe-base64-helper.js';

/**
 * DEFAULT_EXPIRATION is set to seconds in 12 hours
 */
const DEFAULT_EXPIRATION_SECONDS = 12 * 60 * 60;

// Maximum expiration is 24 hours according. (See VAPID spec)
const MAX_EXPIRATION_SECONDS = 24 * 60 * 60;

const ECPrivateKeyASN = asn1.define('ECPrivateKey', function() {
  this.seq().obj(
    this.key('version').int(),
    this.key('privateKey').octstr(),
    this.key('parameters').explicit(0).objid()
      .optional(),
    this.key('publicKey').explicit(1).bitstr()
      .optional()
  );
});

function toPEM(key) {
  return ECPrivateKeyASN.encode({
    version: 1,
    privateKey: key,
    parameters: [1, 2, 840, 10045, 3, 1, 7] // prime256v1
  }, 'pem', {
    label: 'EC PRIVATE KEY'
  });
}

export async function generateVAPIDKeys() {
  // Generate ECDSA key pair using Web Crypto API
  const keyPair = await (globalThis.crypto || window.crypto).subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    true,
    ['sign', 'verify']
  );

  // Export the public key in uncompressed raw format (04 || X || Y)
  const publicKeyRaw = await (globalThis.crypto || window.crypto).subtle.exportKey('raw', keyPair.publicKey);
  // Export the private key in pkcs8 format, then extract the raw 32 bytes
  const privateKeyPkcs8 = new Uint8Array(await (globalThis.crypto || window.crypto).subtle.exportKey('pkcs8', keyPair.privateKey));

  // Extract the private key bytes from PKCS8 (last 32 bytes)
  const privateKeyRaw = privateKeyPkcs8.slice(-32);

  // Padding is not needed as Web Crypto always outputs correct length, but for compatibility:
  let privateKeyBuffer = Buffer.from(privateKeyRaw);
  let publicKeyBuffer = Buffer.from(new Uint8Array(publicKeyRaw));

  if (privateKeyBuffer.length < 32) {
    const padding = Buffer.alloc(32 - privateKeyBuffer.length);
    padding.fill(0);
    privateKeyBuffer = Buffer.concat([padding, privateKeyBuffer]);
  }

  if (publicKeyBuffer.length < 65) {
    const padding = Buffer.alloc(65 - publicKeyBuffer.length);
    padding.fill(0);
    publicKeyBuffer = Buffer.concat([padding, publicKeyBuffer]);
  }

  return {
    publicKey: publicKeyBuffer.toString('base64url'),
    privateKey: privateKeyBuffer.toString('base64url')
  };
}

export function validateSubject(subject) {
  if (!subject) {
    throw new Error('No subject set in vapidDetails.subject.');
  }

  if (typeof subject !== 'string' || subject.length === 0) {
    throw new Error('The subject value must be a string containing an https: URL or '
    + 'mailto: address. ' + subject);
  }

  let subjectParseResult = null;
  try {
    subjectParseResult = new URL(subject);
  } catch (err) {
    throw new Error('Vapid subject is not a valid URL. ' + subject);
  }
  if (!['https:', 'mailto:'].includes(subjectParseResult.protocol)) {
    throw new Error('Vapid subject is not an https: or mailto: URL. ' + subject);
  }
  if (subjectParseResult.hostname === 'localhost') {
    console.warn('Vapid subject points to a localhost web URI, which is unsupported by '
      + 'Apple\'s push notification server and will result in a BadJwtToken error when '
      + 'sending notifications.');
    }
}

export function validatePublicKey(publicKey) {
  if (!publicKey) {
    throw new Error('No key set vapidDetails.publicKey');
  }

  if (typeof publicKey !== 'string') {
    throw new Error('Vapid public key is must be a URL safe Base 64 '
    + 'encoded string.');
  }

  if (!urlBase64Helper.validate(publicKey)) {
    throw new Error('Vapid public key must be a URL safe Base 64 (without "=")');
  }

  publicKey = Buffer.from(publicKey, 'base64url');

  if (publicKey.length !== 65) {
    throw new Error('Vapid public key should be 65 bytes long when decoded.');
  }
}

export function validatePrivateKey(privateKey) {
  if (!privateKey) {
    throw new Error('No key set in vapidDetails.privateKey');
  }

  if (typeof privateKey !== 'string') {
    throw new Error('Vapid private key must be a URL safe Base 64 '
    + 'encoded string.');
  }

  if (!urlBase64Helper.validate(privateKey)) {
    throw new Error('Vapid private key must be a URL safe Base 64 (without "=")');
  }

  privateKey = Buffer.from(privateKey, 'base64url');

  if (privateKey.length !== 32) {
    throw new Error('Vapid private key should be 32 bytes long when decoded.');
  }
}

/**
 * Given the number of seconds calculates
 * the expiration in the future by adding the passed `numSeconds`
 * with the current seconds from Unix Epoch
 *
 * @param {Number} numSeconds Number of seconds to be added
 * @return {Number} Future expiration in seconds
 */
export function getFutureExpirationTimestamp(numSeconds) {
  const futureExp = new Date();
  futureExp.setSeconds(futureExp.getSeconds() + numSeconds);
  return Math.floor(futureExp.getTime() / 1000);
}

/**
 * Validates the Expiration Header based on the VAPID Spec
 * Throws error of type `Error` if the expiration is not validated
 *
 * @param {Number} expiration Expiration seconds from Epoch to be validated
 */
export function validateExpiration(expiration) {
  if (!Number.isInteger(expiration)) {
    throw new Error('`expiration` value must be a number');
  }

  if (expiration < 0) {
    throw new Error('`expiration` must be a positive integer');
  }

  // Roughly checks the time of expiration, since the max expiration can be ahead
  // of the time than at the moment the expiration was generated
  const maxExpirationTimestamp = getFutureExpirationTimestamp(MAX_EXPIRATION_SECONDS);

  if (expiration >= maxExpirationTimestamp) {
    throw new Error('`expiration` value is greater than maximum of 24 hours');
  }
}

/**
 * This method takes the required VAPID parameters and returns the required
 * header to be added to a Web Push Protocol Request.
 * @param  {string} audience        This must be the origin of the push service.
 * @param  {string} subject         This should be a URL or a 'mailto:' email
 * address.
 * @param  {string} publicKey       The VAPID public key.
 * @param  {string} privateKey      The VAPID private key.
 * @param  {string} contentEncoding The contentEncoding type.
 * @param  {integer} [expiration]   The expiration of the VAPID JWT.
 * @return {Object}                 Returns an Object with the Authorization and
 * 'Crypto-Key' values to be used as headers.
 */
export async function getVapidHeaders(audience, subject, publicKey, privateKey, contentEncoding, expiration) {
  if (!audience) {
    throw new Error('No audience could be generated for VAPID.');
  }

  if (typeof audience !== 'string' || audience.length === 0) {
    throw new Error('The audience value must be a string containing the '
    + 'origin of a push service. ' + audience);
  }

  try {
    new URL(audience); // eslint-disable-line no-new
  } catch (err) {
    throw new Error('VAPID audience is not a url. ' + audience);
  }

  validateSubject(subject);
  validatePublicKey(publicKey);
  validatePrivateKey(privateKey);

  privateKey = Buffer.from(privateKey, 'base64url');

  if (expiration) {
    validateExpiration(expiration);
  } else {
    expiration = getFutureExpirationTimestamp(DEFAULT_EXPIRATION_SECONDS);
  }

  const header = {
    typ: 'JWT',
    alg: 'ES256'
  };

  const jwtPayload = {
    aud: audience,
    exp: expiration,
    sub: subject
  };

  // jose expects a CryptoKey or KeyObject for signing
  const pem = toPEM(privateKey);
  const jwt = await new SignJWT(jwtPayload)
    .setProtectedHeader(header)
    .setAudience(audience)
    .setExpirationTime(expiration)
    .setSubject(subject)
    .sign({ key: pem, format: 'pem', passphrase: '' });

  if (contentEncoding === WebPushConstants.supportedContentEncodings.AES_128_GCM) {
    return {
      Authorization: 'vapid t=' + jwt + ', k=' + publicKey
    };
  }
  if (contentEncoding === WebPushConstants.supportedContentEncodings.AES_GCM) {
    return {
      Authorization: 'WebPush ' + jwt,
      'Crypto-Key': 'p256ecdsa=' + publicKey
    };
  }

  throw new Error('Unsupported encoding type specified.');
}
