import url from 'url';
import https from 'https';

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

WebPushLib.prototype.generateRequestDetails = function(subscription, payload, options) {
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
    }

    let currentVapidDetails = vapidDetails;
    let timeToLive = DEFAULT_TTL;
    let extraHeaders = {};
    let contentEncoding = webPushConstants.supportedContentEncodings.AES_128_GCM;
    let urgency = webPushConstants.supportedUrgency.NORMAL;
    let topic;
    let proxy;
    let agent;
    let timeout;

    if (options) {
      const validOptionKeys = [
        'headers',
        'vapidDetails',
        'TTL',
        'contentEncoding',
        'urgency',
        'topic',
        'proxy',
        'agent',
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

      if (options.proxy) {
        if (typeof options.proxy === 'string'
          || typeof options.proxy.host === 'string') {
          proxy = options.proxy;
        } else {
          console.warn('Attempt to use proxy option, but invalid type it should be a string or proxy options object.');
        }
      }

      if (options.agent) {
        if (options.agent instanceof https.Agent) {
          if (proxy) {
            console.warn('Agent option will be ignored because proxy option is defined.');
          }

          agent = options.agent;
        } else {
          console.warn('Wrong type for the agent option, it should be an instance of https.Agent.');
        }
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
      const encrypted = encryptionHelper
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
      const parsedUrl = url.parse(subscription.endpoint);
      const audience = parsedUrl.protocol + '//'
      + parsedUrl.host;

      const vapidHeaders = vapidHelper.getVapidHeaders(
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

    if (proxy) {
      requestDetails.proxy = proxy;
    }

    if (agent) {
      requestDetails.agent = agent;
    }

    if (timeout) {
      requestDetails.timeout = timeout;
    }

    return requestDetails;
  };

WebPushLib.prototype.sendNotification = function(subscription, payload, options) {
    let requestDetails;
    try {
      requestDetails = this.generateRequestDetails(subscription, payload, options);
    } catch (err) {
      return Promise.reject(err);
    }

    return new Promise(function(resolve, reject) {
      const httpsOptions = {};
      const urlParts = url.parse(requestDetails.endpoint);
      httpsOptions.hostname = urlParts.hostname;
      httpsOptions.port = urlParts.port;
      httpsOptions.path = urlParts.path;

      httpsOptions.headers = requestDetails.headers;
      httpsOptions.method = requestDetails.method;

      if (requestDetails.timeout) {
        httpsOptions.timeout = requestDetails.timeout;
      }

      if (requestDetails.agent) {
        httpsOptions.agent = requestDetails.agent;
      }

      if (requestDetails.proxy) {
        const { HttpsProxyAgent } = require('https-proxy-agent');
        httpsOptions.agent = new HttpsProxyAgent(requestDetails.proxy);
      }

      const pushRequest = https.request(httpsOptions, function(pushResponse) {
        let responseText = '';

        pushResponse.on('data', function(chunk) {
          responseText += chunk;
        });

        pushResponse.on('end', function() {
          if (pushResponse.statusCode < 200 || pushResponse.statusCode > 299) {
            reject(new WebPushError(
              'Received unexpected response code',
              pushResponse.statusCode,
              pushResponse.headers,
              responseText,
              requestDetails.endpoint
            ));
          } else {
            resolve({
              statusCode: pushResponse.statusCode,
              body: responseText,
              headers: pushResponse.headers
            });
          }
        });
      });

      if (requestDetails.timeout) {
        pushRequest.on('timeout', function() {
          pushRequest.destroy(new Error('Socket timeout'));
        });
      }

      pushRequest.on('error', function(e) {
        reject(e);
      });

      if (requestDetails.body) {
        pushRequest.write(requestDetails.body);
      }

      pushRequest.end();
    });
};
