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

    /*  Symmetric encryption used in CryptPad's one-to-one chat system
    */
    var Curve = Crypto.Curve = {};

    var concatenateUint8s = function (A) {
        var len = 0;
        var offset = 0;
        A.forEach(function (uints) {
            len += uints.length || 0;
        });
        var c = new Uint8Array(len);
        A.forEach(function (x) {
            c.set(x, offset);
            offset += x.length;
        });
        return c;
    };

    var encodeBase64 = Nacl.util.encodeBase64;
    var decodeBase64 = Nacl.util.decodeBase64;
    var decodeUTF8 = Nacl.util.decodeUTF8;
    var encodeUTF8 = Nacl.util.encodeUTF8;

    Curve.encrypt = function (message, secret) {
        var buffer = decodeUTF8(message);
        var nonce = Nacl.randomBytes(24);
        var box = Nacl.box.after(buffer, nonce, secret);
        return encodeBase64(nonce) + '|' + encodeBase64(box);
    };

    Curve.decrypt = function (packed, secret) {
        var unpacked = packed.split('|');
        var nonce = decodeBase64(unpacked[0]);
        var box = decodeBase64(unpacked[1]);
        var message = Nacl.box.open.after(box, nonce, secret);
        if (message === false) { return null; }
        return encodeUTF8(message);
    };

    Curve.signAndEncrypt = function (msg, cryptKey, signKey) {
        var packed = Curve.encrypt(msg, cryptKey);
        return encodeBase64(Nacl.sign(decodeUTF8(packed), signKey));
    };

    Curve.openSigned = function (msg, cryptKey /*, validateKey STUBBED*/) {
        var content = decodeBase64(msg).subarray(64);
        return Curve.decrypt(encodeUTF8(content), cryptKey);
    };

    Curve.deriveKeys = function (theirs, mine) {
        try {
            var pub = decodeBase64(theirs);
            var secret = decodeBase64(mine);

            var sharedSecret = Nacl.box.before(pub, secret);
            var salt = decodeUTF8('CryptPad.signingKeyGenerationSalt');

            // 64 uint8s
            var hash = Nacl.hash(concatenateUint8s([salt, sharedSecret]));
            var signKp = Nacl.sign.keyPair.fromSeed(hash.subarray(0, 32));
            var cryptKey = hash.subarray(32, 64);

            return {
                cryptKey: encodeBase64(cryptKey),
                signKey: encodeBase64(signKp.secretKey),
                validateKey: encodeBase64(signKp.publicKey)
            };
        } catch (e) {
            console.error('invalid keys or other problem deriving keys');
            console.error(e);
            return null;
        }
    };

    Curve.createEncryptor = function (keys) {
        if (!keys || typeof(keys) !== 'object') {
            return void console.error("invalid input for createEncryptor");
        }

        var cryptKey = decodeBase64(keys.cryptKey);
        var signKey = decodeBase64(keys.signKey);
        var validateKey = decodeBase64(keys.validateKey);

        return {
            encrypt: function (msg) {
                return Curve.signAndEncrypt(msg, cryptKey, signKey);
            },
            decrypt: function (packed) {
                return Curve.openSigned(packed, cryptKey, validateKey);
            }
        };
    };

/*  Mailbox encryption

Assuming an API for appending messages to a public append-only log...
Define an encryption scheme which:
1. protects the plaintexts of appended messages from all but their authors and the holder of an asymmetric keypair
2. optionally proves authorship of the message to the recipient
3. guarantees unlinkability of appended ciphertexts in the absence of the private key

Accomplish this by:
1. encrypting a message with the recipient's public key and your own private key
2. encrypting the resulting ciphertext with an ephemeral key

Use-cases...
1. leave a message for a friend
2. publish a post to a private mailing list
3. submit private data to a public form
4. cast an authenticated vote in public
5. use the public log as a mixnet, leaving messages for undisclosed recipients

*/

    var u8_concat = function (A) {
        // expect a list of uint8Arrays
        var length = 0;
        A.forEach(function (a) { length += a.length; });
        var total = new Uint8Array(length);

        var offset = 0;
        A.forEach(function (a) {
            total.set(a, offset);
            offset += a.length;
        });
        return total;
    };

    var u8_slice = function (A, start, end) {
        return new Uint8Array(Array.prototype.slice.call(A, start, end));
    };

    // INTERNAL USE ONLY
    var asymmetric_encrypt = function (u8_plain, keys) {
        // generate a random nonce
        var u8_nonce = Nacl.randomBytes(Nacl.box.nonceLength);

        // basic symmetric encryption using named parameters to avoid misuse
        var u8_cipher = Nacl.box(
            u8_plain,
            u8_nonce,
            keys.their_public,
            keys.my_private
        );

        /*  bundle the necessary paramaters into a single Uint8Array.
            order the nonce first in case we ever want to refer use the first
            n bytes of a ciphertext to identify messages.  */
        var u8_bundle = u8_concat([
            u8_nonce, // 24 uint8s
            keys.their_public, // 32 uint8s
            u8_cipher, // arbitrary length
        ]);

        return u8_bundle;
    };

    // INTERNAL USE ONLY
    // throws on decryption errors
    var asymmetric_decrypt = function (u8_bundle, keys) {
        // parse out the nonce
        var u8_nonce = u8_slice(u8_bundle, 0, Nacl.box.nonceLength);

        // parse out the sender's public key
        var u8_sender_public = u8_slice(
            u8_bundle,
            Nacl.box.nonceLength,
            Nacl.box.nonceLength + Nacl.box.publicKeyLength
        );

        // take the remaining ciphertext
        var u8_cipher = u8_slice(
            u8_bundle,
            Nacl.box.nonceLength + Nacl.box.publicKeyLength
        );

        // decrypt the ciphertext using the private key
        var u8_plain = Nacl.box.open(
            u8_cipher,
            u8_nonce,
            u8_sender_public,
            keys.my_private
        );

        if (!u8_plain) { throw new Error('E_DECRYPTION_FAILURE'); }

        // return the ciphertext and sender's public key
        return {
            content: u8_plain,
            author: u8_sender_public,
        };
    };

    var Mailbox = Crypto.Mailbox = {};

    // TODO wrap up the above methods in a nice manner
    Mailbox.createEncryptor = function () {
        asymmetric_decrypt = asymmetric_decrypt;
        asymmetric_encrypt = asymmetric_encrypt;
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

