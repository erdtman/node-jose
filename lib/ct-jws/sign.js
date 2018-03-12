/*!
 * jws/sign.js - Sign to JWS
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var clone = require("lodash.clone"),
    intersection = require("lodash.intersection"),
    omit = require("lodash.omit"),
    merge = require("lodash.merge"),
    uniq = require("lodash.uniq"),
    util = require("../util"),
    JWK = require("../jwk"),
    slice = require("./helpers").slice;

var DEFAULTS = require("./defaults");

function isObject (item) {
  return item && typeof item === "object" && !Array.isArray(item);
}

/**
 * @class JWS.Signer
 * @classdesc Generator of signed content.
 *
 * @description
 * **NOTE:** this class cannot be instantiated directly. Instead call {@link
 * JWS.createSign}.
 */
var JWSSigner = function(signatories) {
  var finalized = false,
      content = new Buffer(0);

  /**
  * @method JWS.Signer#final
  * @description
  * Finishes the signature operation.
  *
  * The returned Promise, when fulfilled, is the JSON Web Signature (JWS)
  * object.
  *
  * @param {Buffer|String} [data] The final content to apply.
  * @param {String} [encoding="binary"] The encoding of the final content
  *        (if any).
  * @returns {Promise} The promise for the signatures
  * @throws {Error} If a signature has already been generated.
  */
  Object.defineProperty(this, "sign", {
    value: function(data, encoding) {
      if (finalized) {
        return Promise.reject(new Error("already final"));
      }

      if (!isObject(data)) {
        return Promise.reject(new Error("Data to sign must be an object"));
      }

      // mark as done...ish
      finalized = true;

      // map signatory promises to just signatories
      data.__cleartext_signature = {} // TODO make name configurable
      var promise = Promise.all(signatories);

      promise = promise.then(function(sigs) {
        var result = {'sigs': sigs, 'globalHeaders': {}};
        if(sigs.length !== 1) {
          var keys = [];
          sigs.forEach(s => keys.push(Object.keys(s.header)));
          var inter = intersection(...keys); // Get all common headers
          inter.forEach(key => {
            var values = sigs.map(a => a.header[key]);
            if (values.reduce((a, b) => a === b)) {
                result.globalHeaders[key] = values[0]; // All values are equal
            }
          });
        }
        return result;
      });

      promise = promise.then(function(input) {
        var sigs = input.sigs;
        sigs = sigs.map(function(s) {
          if(sigs.length === 1) {
            data.__cleartext_signature = s.header;
          } else {
            data.__cleartext_signature = input.globalHeaders;
            data.__cleartext_signature.signers = [omit(s.header, Object.keys(input.globalHeaders))];
          }

          var headers = omit(s.header, Object.keys(input.globalHeaders));
          var tbs = new Buffer(JSON.stringify(data), "utf8");
          s = s.key.sign(s.header.alg, tbs, s.header);
          s = s.then(function(result) {
            headers.signature = util.base64url.encode(result.mac);
            return headers;
          });
          return s;
        });
        return Promise.all(sigs);
      });

      promise = promise.then(function(sigs) {
        if(sigs.length === 1) {
          data.__cleartext_signature = sigs[0]; // TODO make name configurable
        } else {
          data.__cleartext_signature.signers = sigs;
        }
        return data;
      })

      return promise;
    }
  });
};


/**
 * @description
 * Creates a new JWS.Signer with the given options and signatories.
 *
 * @param {Object} [opts] The signing options
 * @param {Object} [opts.fields] Additional header fields
 * @param {JWK.Key[]|Object[]} [signs] Signatories, either as an array of
 *        JWK.Key instances; or an array of objects, each with the following
 *        properties
 * @param {JWK.Key} signs.key Key used to sign content
 * @param {Object} [signs.header] Per-signatory header fields
 * @param {String} [signs.reference] Reference field to identify the key
 * @param {String[]|String} [signs.protect] List of fields to integrity
 *        protect ("*" to protect all fields)
 * @returns {JWS.Signer} The signature generator.
 * @throws {Error} If Compact serialization is requested but there are
 *         multiple signatories
 */
function createSign(opts, signs) {
  // fixup signatories
  var options = opts,
      signStart = 1,
      signList = signs;

  if (arguments.length === 0) {
    throw new Error("at least one signatory must be provided");
  }
  if (arguments.length === 1) {
    signList = opts;
    signStart = 0;
    options = {};
  } else if (JWK.isKey(opts) ||
            (opts && "kty" in opts) ||
            (opts && "key" in opts &&
            (JWK.isKey(opts.key) || "kty" in opts.key))) {
    signList = opts;
    signStart = 0;
    options = {};
  } else {
    options = clone(opts);
  }
  if (!Array.isArray(signList)) {
    signList = slice(arguments, signStart);
  }

  // fixup options
  options = merge(clone(DEFAULTS), options);

  // setup header fields
  var allFields = options.fields || {};

  signList = signList.map(function(s, idx) {
    var p;

    // resolve a key
    if (s && "kty" in s) {
      p = JWK.asKey(s);
      p = p.then(function(k) {
        return {
          key: k
        };
      });
    } else if (s) {
      p = JWK.asKey(s.key);
      p = p.then(function(k) {
        return {
          header: s.header,
          reference: s.reference,
          protect: s.protect,
          key: k
        };
      });
    } else {
      p = Promise.reject(new Error("missing key for signatory " + idx));
    }

    // resolve the complete signatory
    p = p.then(function(signatory) {
      var key = signatory.key;

      // make sure there is a header
      var header = signatory.header || {};
      header = merge(merge({}, allFields), header);
      signatory.header = header;

      // ensure an algorithm
      if (!header.alg) {
        header.alg = key.algorithms(JWK.MODE_SIGN)[0] || "";
      }

      // determine the key reference
      var ref = signatory.reference;
      delete signatory.reference;
      if (undefined === ref) {
        // header already contains the key reference
        ref = ["kid", "jku", "x5c", "x5t", "x5u"].some(function(k) {
          return (k in header);
        });
        ref = !ref ? "kid" : null;
      } else if ("boolean" === typeof ref) {
        // explicit (positive | negative) request for key reference
        ref = ref ? "kid" : null;
      }
      var jwk;
      if (ref) {
        jwk = key.toJSON();
        if ("jwk" === ref) {
          if ("oct" === key.kty) {
            return Promise.reject(new Error("cannot embed key"));
          }
          header.jwk = jwk;
        } else if (ref in jwk) {
          header[ref] = jwk[ref];
        }
      }

      // freeze signatory
      signatory = Object.freeze(signatory);
      return signatory;
    });

    return p;
  });

  return new JWSSigner(signList);
}

module.exports = {
  signer: JWSSigner,
  createSign: createSign
};
