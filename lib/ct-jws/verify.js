/*!
 * jws/verify.js - Verifies from a JWS
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var clone = require("lodash.clone"),
    cloneDeep = require("lodash.cloneDeep"),
    merge = require("lodash.merge"),
    omit = require("lodash.omit"),
    base64url = require("../util/base64url"),
    AlgConfig = require("../util/algconfig"),
    JWK = require("../jwk");

var DEFAULT_OPTIONS = {
  algorithms: "*",
  allowEmbeddedKey: false
};

function isObject (item) {
  return item && typeof item === "object" && !Array.isArray(item);
}

function getAlgKey(opts, sig, assumedKey, keystore) {
  if (opts.allowEmbeddedKey && sig.header.jwk) {
    return JWK.asKey(sig.jwk);
  } else if (opts.allowEmbeddedKey && sig.header.x5c) {
    // TODO: callback to validate chain
    return JWK.asKey(new Buffer(sig.header.x5c[0], "base64"), "pkix");
  } else {
    return Promise.resolve(assumedKey || keystore.get({
      use: "sig",
      alg: sig.header.alg,
      kid: sig.header.kid
    }));
  }
}

/**
 * @class JWS.Verifier
 * @classdesc Parser of signed content.
 *
 * @description
 * **NOTE:** this class cannot be instantiated directly. Instead call {@link
 * JWS.createVerify}.
 */
var JWSVerifier = function(ks, globalOpts) {
  var assumedKey,
      keystore;

  if (JWK.isKey(ks)) {
    assumedKey = ks;
    keystore = assumedKey.keystore;
  } else if (JWK.isKeyStore(ks)) {
    keystore = ks;
  } else {
    keystore = JWK.createKeyStore();
  }

  globalOpts = merge(DEFAULT_OPTIONS, globalOpts);

  Object.defineProperty(this, "defaultKey", {
    value: assumedKey || undefined,
    enumerable: true
  });
  Object.defineProperty(this, "keystore", {
    value: keystore,
    enumerable: true
  });

  Object.defineProperty(this, "verify", {
    value: function(input, opts) {
      opts = merge({}, globalOpts, opts || {});
      var algSpec = new AlgConfig(opts.algorithms);

      if ("string" === typeof input) {
        input = JSON.parse(intput);
      }

      if (!isObject(input)) {
        throw new Error("Input has to be a JOSN object.");
      }
      var data = cloneDeep(input);
      var sigs = data.__cleartext_signature.signers || [data.__cleartext_signature];

      // TODO add crit support
      // TODO add preverify hooks
      // TODO add post verify hooks
      sigs = sigs.map(function(sig, index) {
        var signee = omit(sig || {}, ['valid', 'message']);
        var header = merge({}, signee, omit(data.__cleartext_signature, ['signers']));
        var signature = base64url.decode(signee.signature);
        delete signee.signature;
        if (!algSpec.match(header.alg)) {
          return Promise.reject(new Error("Algorithm not allowed: " + header.alg));
        }
        sig = {
          'signee': signee,
          'header': header,
          'signature': signature
        };
        return getAlgKey(opts, sig, assumedKey, keystore).then(function(key) {
          if (!key) {
            return Promise.reject(new Error("Key does not match"));
          }
          sig.key = key;
          return sig;
        }).then(function(sig) {
          if(sigs.length === 1) {
            data.__cleartext_signature = sig.signee;
          } else {
            data.__cleartext_signature.signers = [sig.signee];
          }
          var tbv = new Buffer(JSON.stringify(data), "utf8");
          return sig.key.verify(header.alg,tbv,signature);
        }).then(function(result) {
          if(sigs.length !== 1) {
            input.__cleartext_signature.signers[index].valid = result.valid;
          }
          return input
        }).catch((error) => {
          if(sigs.length !== 1) {
            input.__cleartext_signature.signers[index].valid = false;
            input.__cleartext_signature.signers[index].message = error.message;
          } else {
            input.__cleartext_signature.valid = false;
            input.__cleartext_signature.message = error.message;
          }
          return false;
        });
      });

      return Promise.all(sigs).then(function(){
        return input;
      });
    }
  });
};

/**
 * @description
 * Creates a new JWS.Verifier with the given Key or KeyStore.
 *
 * @param {JWK.Key|JWK.KeyStore} ks The Key or KeyStore to use for verification.
 * @returns {JWS.Verifier} The new Verifier.
 */
function createVerify(ks, opts) {
  var vfy = new JWSVerifier(ks, opts);

  return vfy;
}

module.exports = {
  verifier: JWSVerifier,
  createVerify: createVerify
};
