import WebPushError from './web-push-error.js';
import * as vapidHelper from './vapid-helper.js';
import * as encryptionHelper from './encryption-helper.js';
import webPushConstants from './web-push-constants.js';
import * as urlBase64Helper from './urlsafe-base64-helper.js';

const DEFAULT_TTL = 2419200;

let vapidDetails;

export function WebPushLib() {

}

WebPushLib.prototype.setVapidDetails = function(subject, publicKey, privateKey) {
    if (arguments.length === 1 && arguments[0] === null) {
      vapidDetails = null;
      return;
    }

    vapidHelper.validateSubject(subject);
    vapidHelper.validatePublicKey(publicKey);
    vapidHelper.validatePrivateKey(privateKey);

    vapidDetails = {
      subject: subject,
      publicKey: publicKey,
      privateKey: privateKey
    };
  };

WebPushLib.prototype.generateRequestDetails = async function(subscription, payload, options) {
    if (!subscription || !subscription.endpoint) {
      throw new Error('You must pass in a subscription with at least '
      + 'an endpoint.');
    }

    if (typeof subscription.endpoint !== 'string'
    || subscription.endpoint.length === 0) {
      throw new Error('The subscription endpoint must be a string with '
      + 'a valid URL.');
    }

    if (payload) {
      if (typeof subscription !== 'object' || !subscription.keys
      || !subscription.keys.p256dh
      || !subscription.keys.auth) {
        throw new Error('To send a message with a payload, the '
        + 'subscription must have \'auth\' and \'p256dh\' keys.');
      }
      if (typeof subscription.keys.p256dh !== 'string' || subscription.keys.p256dh.length === 0) {
        throw new Error('The subscription.keys.p256dh value must be a non-empty string.');
      }
      if (typeof subscription.keys.auth !== 'string' || subscription.keys.auth.length === 0) {
        throw new Error('The subscription.keys.auth value must be a non-empty string.');
      }
    }

    let currentVapidDetails = vapidDetails;
    let timeToLive = DEFAULT_TTL;
    let extraHeaders = {};
    let contentEncoding = webPushConstants.supportedContentEncodings.AES_128_GCM;
    let urgency = webPushConstants.supportedUrgency.NORMAL;
    let topic;
    let timeout;

    if (options) {
      const validOptionKeys = [
        'headers',
        'vapidDetails',
        'TTL',
        'contentEncoding',
        'urgency',
        'topic',
        'timeout'
      ];
      const optionKeys = Object.keys(options);
      for (let i = 0; i < optionKeys.length; i += 1) {
        const optionKey = optionKeys[i];
        if (!validOptionKeys.includes(optionKey)) {
          throw new Error('\'' + optionKey + '\' is an invalid option. '
          + 'The valid options are [\'' + validOptionKeys.join('\', \'')
          + '\'].');
        }
      }

      if (options.headers) {
        extraHeaders = options.headers;
        let duplicates = Object.keys(extraHeaders)
            .filter(function (header) {
              return typeof options[header] !== 'undefined';
            });

        if (duplicates.length > 0) {
          throw new Error('Duplicated headers defined ['
          + duplicates.join(',') + ']. Please either define the header in the'
          + 'top level options OR in the \'headers\' key.');
        }
      }

      if (options.vapidDetails !== undefined) {
        currentVapidDetails = options.vapidDetails;
      }

      if (options.TTL !== undefined) {
        timeToLive = Number(options.TTL);
        if (timeToLive < 0) {
          throw new Error('TTL should be a number and should be at least 0');
        }
      }

      if (options.contentEncoding) {
        if ((options.contentEncoding === webPushConstants.supportedContentEncodings.AES_128_GCM
          || options.contentEncoding === webPushConstants.supportedContentEncodings.AES_GCM)) {
          contentEncoding = options.contentEncoding;
        } else {
          throw new Error('Unsupported content encoding specified.');
        }
      }

      if (options.urgency) {
        if ((options.urgency === webPushConstants.supportedUrgency.VERY_LOW
          || options.urgency === webPushConstants.supportedUrgency.LOW
          || options.urgency === webPushConstants.supportedUrgency.NORMAL
          || options.urgency === webPushConstants.supportedUrgency.HIGH)) {
          urgency = options.urgency;
        } else {
          throw new Error('Unsupported urgency specified.');
        }
      }

      if (options.topic) {
        if (!urlBase64Helper.validate(options.topic)) {
          throw new Error('Unsupported characters set use the URL or filename-safe Base64 characters set');
        }
        if (options.topic.length > 32) {
          throw new Error('use maximum of 32 characters from the URL or filename-safe Base64 characters set');
        }
        topic = options.topic;
      }

      if (typeof options.timeout === 'number') {
        timeout = options.timeout;
      }
    }

    if (typeof timeToLive === 'undefined') {
      timeToLive = DEFAULT_TTL;
    }

    const requestDetails = {
      method: 'POST',
      headers: {
        TTL: timeToLive
      }
    };
    Object.keys(extraHeaders).forEach(function (header) {
      requestDetails.headers[header] = extraHeaders[header];
    });
    let requestPayload = null;

    if (payload) {
      const encrypted = await encryptionHelper
        .encrypt(subscription.keys.p256dh, subscription.keys.auth, payload, contentEncoding);

      requestDetails.headers['Content-Length'] = encrypted.cipherText.length;
      requestDetails.headers['Content-Type'] = 'application/octet-stream';

      if (contentEncoding === webPushConstants.supportedContentEncodings.AES_128_GCM) {
        requestDetails.headers['Content-Encoding'] = webPushConstants.supportedContentEncodings.AES_128_GCM;
      } else if (contentEncoding === webPushConstants.supportedContentEncodings.AES_GCM) {
        requestDetails.headers['Content-Encoding'] = webPushConstants.supportedContentEncodings.AES_GCM;
        requestDetails.headers.Encryption = 'salt=' + encrypted.salt;
        requestDetails.headers['Crypto-Key'] = 'dh=' + encrypted.localPublicKey.toString('base64url');
      }

      requestPayload = encrypted.cipherText;
    } else {
      requestDetails.headers['Content-Length'] = 0;
    }

    if (currentVapidDetails) {
      // Use standard URL class instead of url.parse
      const parsedUrl = new URL(subscription.endpoint);
      const audience = parsedUrl.protocol + '//' + parsedUrl.host;

      const vapidHeaders = await vapidHelper.getVapidHeaders(
        audience,
        currentVapidDetails.subject,
        currentVapidDetails.publicKey,
        currentVapidDetails.privateKey,
        contentEncoding
      );

      requestDetails.headers.Authorization = vapidHeaders.Authorization;

      if (contentEncoding === webPushConstants.supportedContentEncodings.AES_GCM) {
        if (requestDetails.headers['Crypto-Key']) {
          requestDetails.headers['Crypto-Key'] += ';'
          + vapidHeaders['Crypto-Key'];
        } else {
          requestDetails.headers['Crypto-Key'] = vapidHeaders['Crypto-Key'];
        }
      }
    }

    requestDetails.headers.Urgency = urgency;

    if (topic) {
      requestDetails.headers.Topic = topic;
    }

    requestDetails.body = requestPayload;
    requestDetails.endpoint = subscription.endpoint;

    if (timeout) {
      requestDetails.timeout = timeout;
    }

    return requestDetails;
  };

WebPushLib.prototype.sendNotification = async function(subscription, payload, options) {
    let requestDetails;
    try {
      requestDetails = await this.generateRequestDetails(subscription, payload, options);
    } catch (err) {
      return Promise.reject(err);
    }

    // Use fetch instead of https.request
    const fetch = globalThis.fetch || (typeof window !== 'undefined' && window.fetch);
    if (!fetch) {
      return Promise.reject(new Error('Fetch API is not available in this environment.'));
    }

    const fetchOptions = {
      method: requestDetails.method,
      headers: requestDetails.headers,
      body: requestDetails.body || undefined,
      // Note: fetch timeout is not natively supported; workaround below
    };

    let fetchPromise = fetch(requestDetails.endpoint, fetchOptions).then(async (response) => {
      const responseText = await response.text();
      if (!response.ok) {
        throw new WebPushError(
          'Received unexpected response code',
          response.status,
          response.headers,
          responseText,
          requestDetails.endpoint
        );
      }
      return {
        statusCode: response.status,
        body: responseText,
        headers: response.headers
      };
    });

    // Handle timeout if specified
    if (requestDetails.timeout) {
      return Promise.race([
        fetchPromise,
        new Promise((_, reject) => setTimeout(() => reject(new Error('Socket timeout')), requestDetails.timeout))
      ]);
    }
    return fetchPromise;
};
