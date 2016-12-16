define([
    '/bower_components/tweetnacl/nacl-fast.min.js',
], function () {
    var Nacl = window.nacl;
    var module = { exports: {} };
    module.exports.Nacl = Nacl;

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

    var encrypt = module.exports.encrypt = function (msg, key) {
        return encryptStr(msg, key);
    };

    var decrypt = module.exports.decrypt = function (msg, key) {
        return decryptStr(msg, key);
    };

    var parseKey = module.exports.parseKey = function (str) {
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

    var rand64 = module.exports.rand64 = function (bytes) {
        return Nacl.util.encodeBase64(Nacl.randomBytes(bytes));
    };

    var genKey = module.exports.genKey = function () {
        return rand64(18);
    };

    var b64Encode = function (bytes) {
        return Nacl.util.encodeBase64(bytes).replace(/\//g, '-').replace(/=+$/g, '');
    };

    var b64Decode = function (str) {
        return Nacl.util.decodeBase64(str.replace(/\-/g, '/'));
    };

    var b64RemoveSlashes = module.exports.b64RemoveSlashes = function (str) {
        return str.replace(/\//g, '-');
    };

    var b64AddSlashes = module.exports.b64AddSlashes = function (str) {
        return str.replace(/\-/g, '/');
    };

    var createEncryptor = module.exports.createEncryptor = function (input) {
        if (typeof input === 'object') {
            var out = {};
            var key = input.cryptKey;
            if (input.signKey) {
                var signKey = Nacl.util.decodeBase64(input.signKey);
                out.encrypt = function (msg) {
                    return Nacl.util.encodeBase64(Nacl.sign(Nacl.util.decodeUTF8(encrypt(msg, key)), signKey));
                };
            }
            out.decrypt = function (msg, validateKey) {
                if (!validateKey) {
                    return decrypt(msg, key);
                }
                var vKey = Nacl.util.decodeBase64(validateKey);
                return decrypt(Nacl.util.encodeUTF8(Nacl.sign.open(Nacl.util.decodeBase64(msg), vKey)), key);
            };
            return out;
        }
        var key = parseKey(input).cryptKey;
        return {
            encrypt: function (msg) {
                return encrypt(msg, key);
            },
            decrypt: function (msg) {
                return decrypt(msg, key);
            }
        };
    };

    var createEditCryptor = module.exports.createEditCryptor = function (keyStr, seed) {
        try {
            if (!keyStr) {
                if (seed && !seed.length === 18) {
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
    var createViewCryptor = module.exports.createViewCryptor = function (cryptKeyStr) {
        try {
            if (!cryptKeyStr) {
                throw new Error("Cannot open a new pad in read-only mode!");
            }
            return {
                cryptKey: Nacl.util.decodeBase64(cryptKeyStr),
                viewKeyStr: cryptKeyStr
            };
        } catch (err) {
            console.error('[chainpad-crypto.createEditCryptor] invalid string supplied');
            throw err;
        }
    };

    return module.exports;
});
