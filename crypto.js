(function () {
    'use strict';
var factory = function (Nacl) {
    var Crypto = {
        Nacl: Nacl
    };

    var encryptStr = function (str, key) {
        var array = Nacl.util.decodeUTF8(str);
        var nonce = Nacl.randomBytes(24);
        var packed = Nacl.secretbox(array, nonce, key);
        if (!packed) { throw new Error(); }
        return Nacl.util.encodeBase64(nonce) + "|" + Nacl.util.encodeBase64(packed);
    };

    var decryptStr = function (str, key) {
        var arr = str.split('|');
        if (arr.length !== 2) { throw new Error(); }
        var nonce = Nacl.util.decodeBase64(arr[0]);
        var packed = Nacl.util.decodeBase64(arr[1]);
        var unpacked = Nacl.secretbox.open(packed, nonce, key);
        if (!unpacked) { throw new Error(); }
        return Nacl.util.encodeUTF8(unpacked);
    };

    var encrypt = Crypto.encrypt = function (msg, key) {
        return encryptStr(msg, key);
    };

    var decrypt = Crypto.decrypt = function (msg, key) {
        return decryptStr(msg, key);
    };

    var parseKey = Crypto.parseKey = function (str) {
        try {
            var array = Nacl.util.decodeBase64(str);
            var hash = Nacl.hash(array);
            var lk = hash.subarray(32);
            return {
                lookupKey: lk,
                cryptKey: hash.subarray(0,32),
                channel: Nacl.util.encodeBase64(lk).substring(0,10)
            };
        } catch (err) {
            console.error('[chainpad-crypto.parseKey] invalid string supplied');
            throw err;
        }
    };

    var rand64 = Crypto.rand64 = function (bytes) {
        return Nacl.util.encodeBase64(Nacl.randomBytes(bytes));
    };

    Crypto.genKey = function () {
        return rand64(18);
    };

    var b64Encode = function (bytes) {
        return Nacl.util.encodeBase64(bytes).replace(/\//g, '-').replace(/=+$/g, '');
    };

    var b64Decode = function (str) {
        return Nacl.util.decodeBase64(str.replace(/\-/g, '/'));
    };

    Crypto.b64RemoveSlashes = function (str) {
        return str.replace(/\//g, '-');
    };

    Crypto.b64AddSlashes = function (str) {
        return str.replace(/\-/g, '/');
    };

    Crypto.createEncryptor = function (input) {
        var key;
        if (typeof input === 'object') {
            var out = {};
            key = input.cryptKey;
            if (input.signKey) {
                var signKey = Nacl.util.decodeBase64(input.signKey);
                out.encrypt = function (msg) {
                    return Nacl.util.encodeBase64(Nacl.sign(Nacl.util.decodeUTF8(encrypt(msg, key)), signKey));
                };
            }
            out.decrypt = function (msg, validateKey, skipCheck) {
                if (!validateKey) {
                    return decrypt(msg, key);
                }
                // .subarray(64) remove the signature since it's taking lots of time and it's already checked server-side.
                // We only need to check when the message is not coming from history keeper
                var validated = (skipCheck || typeof validateKey !== "string")
                                    ? Nacl.util.decodeBase64(msg).subarray(64)
                                    : Nacl.sign.open(Nacl.util.decodeBase64(msg), Nacl.util.decodeBase64(validateKey));
                if (!validated) { return; }
                return decrypt(Nacl.util.encodeUTF8(validated), key);
            };
            return out;
        }
        key = parseKey(input).cryptKey;
        return {
            encrypt: function (msg) {
                return encrypt(msg, key);
            },
            decrypt: function (msg) {
                return decrypt(msg, key);
            }
        };
    };

    Crypto.createEditCryptor = function (keyStr, seed) {
        try {
            if (!keyStr) {
                if (seed && seed.length !== 18) {
                    throw new Error('expected supplied seed to have length of 18');
                }
                else if (!seed) { seed = Nacl.randomBytes(18); }
                keyStr = Nacl.util.encodeBase64(seed);
            }
            var hash = Nacl.hash(Nacl.util.decodeBase64(keyStr));
            var signKp = Nacl.sign.keyPair.fromSeed(hash.subarray(0, 32));
            var cryptKey = hash.subarray(32, 64);
            return {
                editKeyStr: keyStr,
                signKey: Nacl.util.encodeBase64(signKp.secretKey),
                validateKey: Nacl.util.encodeBase64(signKp.publicKey),
                cryptKey: cryptKey,
                viewKeyStr: b64Encode(cryptKey)
            };
        } catch (err) {
            console.error('[chainpad-crypto.createEditCryptor] invalid string supplied');
            throw err;
        }
    };
    Crypto.createViewCryptor = function (cryptKeyStr) {
        try {
            if (!cryptKeyStr) {
                throw new Error("Cannot open a new pad in read-only mode!");
            }
            return {
                cryptKey: Nacl.util.decodeBase64(cryptKeyStr),
                viewKeyStr: cryptKeyStr
            };
        } catch (err) {
            console.error('[chainpad-crypto.createViewCryptor] invalid string supplied');
            throw err;
        }
    };

    var createViewCryptor2 = Crypto.createViewCryptor2 = function (viewKeyStr, password) {
        try {
            if (!viewKeyStr) {
                throw new Error("Cannot open a new pad in read-only mode!");
            }
            var seed = b64Decode(viewKeyStr);
            var superSeed = seed;
            if (password) {
                var pwKey = Nacl.util.decodeUTF8(password);
                superSeed = new Uint8Array(seed.length + pwKey.length);
                superSeed.set(pwKey);
                superSeed.set(seed, pwKey.length);
            }
            var hash = Nacl.hash(superSeed);
            var chanId = hash.subarray(0,16);
            var cryptKey = hash.subarray(16, 48);
            return {
                viewKeyStr: viewKeyStr,
                cryptKey: cryptKey,
                chanId: b64Encode(chanId)
            };
        } catch (err) {
            console.error('[chainpad-crypto.createViewCryptor2] invalid string supplied');
            throw err;
        }
    };
    Crypto.createEditCryptor2 = function (keyStr, seed, password) {
        try {
            if (!keyStr) {
                if (seed && seed.length !== 18) {
                    throw new Error('expected supplied seed to have length of 18');
                }
                else if (!seed) { seed = Nacl.randomBytes(18); }
                keyStr = b64Encode(seed);
            }
            if (!seed) {
                seed = b64Decode(keyStr);
            }
            var superSeed = seed;
            if (password) {
                var pwKey = Nacl.util.decodeUTF8(password);
                superSeed = new Uint8Array(seed.length + pwKey.length);
                superSeed.set(pwKey);
                superSeed.set(seed, pwKey.length);
            }
            var hash = Nacl.hash(superSeed);
            var signKp = Nacl.sign.keyPair.fromSeed(hash.subarray(0, 32));
            var seed2 = hash.subarray(32, 64);
            var viewKeyStr = b64Encode(seed2);
            var viewCryptor = createViewCryptor2(viewKeyStr, password);
            return {
                editKeyStr: keyStr,
                viewKeyStr: viewKeyStr,
                signKey: Nacl.util.encodeBase64(signKp.secretKey),
                validateKey: Nacl.util.encodeBase64(signKp.publicKey),
                cryptKey: viewCryptor.cryptKey,
                chanId: viewCryptor.chanId
            };
        } catch (err) {
            console.error('[chainpad-crypto.createEditCryptor2] invalid string supplied');
            throw err;
        }
    };

    Crypto.createFileCryptor2 = function (keyStr, password) {
        try {
            var seed;
            if (!keyStr) {
                seed = Nacl.randomBytes(18);
                keyStr = b64Encode(seed);
            }
            if (!seed) {
                seed = b64Decode(keyStr);
            }
            var superSeed = seed;
            if (password) {
                var pwKey = Nacl.util.decodeUTF8(password);
                superSeed = new Uint8Array(seed.length + pwKey.length);
                superSeed.set(pwKey);
                superSeed.set(seed, pwKey.length);
            }
            var hash = Nacl.hash(superSeed);
            var chanId = hash.subarray(0,24);
            var cryptKey = hash.subarray(24, 56);
            return {
                fileKeyStr: keyStr,
                cryptKey: cryptKey,
                chanId: b64Encode(chanId)
            };
        } catch (err) {
            console.error('[chainpad-crypto.createFileCryptor2] invalid string supplied');
            throw err;
        }
    };

    return Crypto;
};

    if (typeof(module) !== 'undefined' && module.exports) {
        module.exports = factory(require('tweetnacl'));
    } else if ((typeof(define) !== 'undefined' && define !== null) && (define.amd !== null)) {
        define([
            '/bower_components/tweetnacl/nacl-fast.min.js',
        ], function () {
            return factory(window.nacl);
        });
    } else {
        factory(window.nacl);
    }
}());

