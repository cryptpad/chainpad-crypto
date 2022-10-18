(function () {
    'use strict';
var factory = function (Nacl) {
    var Crypto = {
        Nacl: Nacl
    };

    var encodeBase64 = Nacl.util.encodeBase64;
    var decodeBase64 = Nacl.util.decodeBase64;
    var decodeUTF8 = Nacl.util.decodeUTF8;
    var encodeUTF8 = Nacl.util.encodeUTF8;
    var encodeHex = function (bytes) {
        var hexString = '';
        for (var i = 0; i < bytes.length; i++) {
            if (bytes[i] < 16) { hexString += '0'; }
            hexString += bytes[i].toString(16);
        }
        return hexString;
    };
/*
    var decodeHex = function (hexString) {
        var bytes = new Uint8Array(Math.ceil(hexString.length / 2));
        for (var i = 0; i < bytes.length; i++) {
            bytes[i] = parseInt(hexString.substr(i * 2, 2), 16);
        }
        return bytes;
    };
*/

    /* Do a symmetric authenticated encryption of str under key using xsalsa20-poly1305.
    Return the concatenated nonce and ciphertext.
    */
    var encryptStr = function (str, key) {
        var array = decodeUTF8(str);
        var nonce = Nacl.randomBytes(24);
        var packed = Nacl.secretbox(array, nonce, key);
        if (!packed) { throw new Error(); }
        return encodeBase64(nonce) + "|" + encodeBase64(packed);
    };

    /* Authenticate and decrypt a str of the form nonce|ciphertext
    Throw an error if authentication fails.
    */
    var decryptStr = function (str, key) {
        var arr = str.split('|');
        if (arr.length !== 2) { throw new Error(); }
        var nonce = decodeBase64(arr[0]);
        var packed = decodeBase64(arr[1]);
        var unpacked = Nacl.secretbox.open(packed, nonce, key);
        if (!unpacked) { throw new Error(); }
        return encodeUTF8(unpacked);
    };

    var encrypt = Crypto.encrypt = function (msg, key) {
        return encryptStr(msg, key);
    };

    var decrypt = Crypto.decrypt = function (msg, key) {
        return decryptStr(msg, key);
    };

    var parseKey = Crypto.parseKey = function (str) {
        try {
            var array = decodeBase64(str);
            var hash = Nacl.hash(array);
            var lk = hash.subarray(32);
            return {
                lookupKey: lk,
                cryptKey: hash.subarray(0,32),
                channel: encodeBase64(lk).substring(0,10)
            };
        } catch (err) {
            console.error('[chainpad-crypto.parseKey] invalid string supplied');
            throw err;
        }
    };

    // Return random bytes encoded as Base64
    var rand64 = Crypto.rand64 = function (bytes) {
        return encodeBase64(Nacl.randomBytes(bytes));
    };

    // Return 18 random bytes
    Crypto.genKey = function () {
        return rand64(18);
    };

    Crypto.b64RemoveSlashes = function (str) {
        return str.replace(/\//g, '-');
    };

    Crypto.b64AddSlashes = function (str) {
        return str.replace(/\-/g, '/');
    };

    var b64Encode = function (bytes) {
        return Crypto.b64RemoveSlashes(encodeBase64(bytes)).replace(/=+$/g, '');
    };

    var b64Decode = function (str) {
        return decodeBase64(Crypto.b64AddSlashes(str));
    };

    /*

* several modes of operation:
  * if input is not an object, use legacy code
  * otherwise
    * get the encryption key
    * get the signing key, if available
    * MAYBE get a validateKey
  * return a pair of functions: {encrypt, decrypt}
    * Encryption contains an inner authenticated symmetric encryption and an outer signing to prove editor permissions.
    * encrypt is not provided, if the input does not contain a signKey.
    * Decryption verifies the ciphertext (unless skipCheck or no validateKey is passed) and decrypts it.
    * The signature is not checked when the message comes from history keeper since it is checked server-side.
    * If the signature does not pass, return void.
    */
    Crypto.createEncryptor = function (input) {
        var key;
        if (typeof input === 'object') {
            var out = {};
            key = input.cryptKey;
            if (!key) { throw new Error("NO_DECRYPTION_KEY_PROVIDED"); }

            if (input.signKey) {
                var signKey = decodeBase64(input.signKey);
                out.encrypt = function (msg) {
                    return encodeBase64(Nacl.sign(decodeUTF8(encrypt(msg, key)), signKey));
                };
            }

            out.decrypt = function (msg, validateKey, skipCheck) {
                if (!validateKey && !skipCheck || validateKey === true && !skipCheck) {
                    console.error("UNEXPECTED_CONFIGURATION");
                    throw new Error("UNSUPPORTED_DECRYPTION_CONFIGURATION");
                }

                // .subarray(64) remove the signature since it's taking lots of time and it's already checked server-side.
                // We only need to check when the message is not coming from history keeper
                var validated = (skipCheck || typeof validateKey !== "string")
                                    ? decodeBase64(msg).subarray(64)
                                    : Nacl.sign.open(decodeBase64(msg), decodeBase64(validateKey));
                if (!validated) { return; }
                return decrypt(encodeUTF8(validated), key);
            };
            return out;
        }
        // Else: Legacy code
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
                // generate a new keyStr from the seed, generate the seed randomly if there is no seed passed.
                if (seed && seed.length !== 18) {
                    throw new Error('expected supplied seed to have length of 18');
                }
                else if (!seed) { seed = Nacl.randomBytes(18); }
                keyStr = encodeBase64(seed);
            }
            var hash = Nacl.hash(decodeBase64(keyStr));
            var signKp = Nacl.sign.keyPair.fromSeed(hash.subarray(0, 32));
            var cryptKey = hash.subarray(32, 64);
            return {
                editKeyStr: keyStr, // allows read+write
                signKey: encodeBase64(signKp.secretKey), // write key
                validateKey: encodeBase64(signKp.publicKey),
                cryptKey: cryptKey, // encrypt/decrypt key
                viewKeyStr: b64Encode(cryptKey) // allows read-only
            };
        } catch (err) {
            console.error('[chainpad-crypto.createEditCryptor] invalid string supplied');
            throw err;
        }
    };

    // Generate viewKeyStr from cryptKeyStr that allows read-only.
    Crypto.createViewCryptor = function (cryptKeyStr) {
        try {
            if (!cryptKeyStr) {
                throw new Error("Cannot open a new pad in read-only mode!");
            }
            return {
                cryptKey: decodeBase64(cryptKeyStr),
                viewKeyStr: cryptKeyStr
            };
        } catch (err) {
            console.error('[chainpad-crypto.createViewCryptor] invalid string supplied');
            throw err;
        }
    };

    // Derive read-only keys and chanId from cryptKeyStr and an optional password.
    var createViewCryptor2 = Crypto.createViewCryptor2 = function (viewKeyStr, password) {
        try {
            if (!viewKeyStr) {
                throw new Error("Cannot open a new pad in read-only mode!");
            }

            // concatenate password and viewKeyStr to obtain the superSeed.
            var seed = b64Decode(viewKeyStr);
            var superSeed = seed;
            if (password) {
                var pwKey = decodeUTF8(password);
                superSeed = new Uint8Array(seed.length + pwKey.length);
                superSeed.set(pwKey);
                superSeed.set(seed, pwKey.length);
            }
            var hash = Nacl.hash(superSeed);
            var chanId = hash.subarray(0,16);
            var cryptKey = hash.subarray(16, 48);

            // Under certain circumstances we want people who have view access to also have
            // a signing capability. This is the case of forms where participants can't
            // edit the schema (chainpad) but can push messages via another channel and need to sign
            // them.
            // This secondary signing key should be derivable from the classic view seed and
            // we can always build a version 1 hash that doesn't contain this informaton.
            var signKp2 = Nacl.sign.keyPair.fromSeed(hash.subarray(32, 64));

            return {
                viewKeyStr: viewKeyStr, // allows read-only
                cryptKey: cryptKey, // encrypt/decrypt
                chanId: b64Encode(chanId),
                secondarySignKey: encodeBase64(signKp2.secretKey), // allows to answer forms
                secondaryValidateKey: encodeBase64(signKp2.publicKey), // allows verifying of answers
            };
        } catch (err) {
            console.error('[chainpad-crypto.createViewCryptor2] invalid string supplied');
            throw err;
        }
    };

    // Derive read+write keys and chanId from cryptKeyStr and an optional password.
    Crypto.createEditCryptor2 = function (keyStr, seed, password) {
        try {
            if (!keyStr) {
                // Generate a new keyStr (and seed, if needed)
                if (seed && seed.length !== 18) {
                    throw new Error('expected supplied seed to have length of 18');
                }
                else if (!seed) { seed = Nacl.randomBytes(18); }
                keyStr = b64Encode(seed);
            }
            if (!seed) {
                seed = b64Decode(keyStr);
            }
            // Concatenate password and seed to superSeed
            var superSeed = seed;
            if (password) {
                var pwKey = decodeUTF8(password);
                superSeed = new Uint8Array(seed.length + pwKey.length);
                superSeed.set(pwKey);
                superSeed.set(seed, pwKey.length);
            }
            var hash = Nacl.hash(superSeed);
            var signKp = Nacl.sign.keyPair.fromSeed(hash.subarray(0, 32));
            // under certain circumstances we want people who have edit access to also have
            // a secondary capability conferred by a symmetric key.
            // This secondary key should be derivable from the classic view hash,
            // but also delegated individually without leaking any information about the editing secrets
            // hashing the secretKey component of the signing keypair accomplishes this
            var secondary = Nacl.hash(signKp.secretKey).subarray(0, Nacl.secretbox.keyLength);

            var seed2 = hash.subarray(32, 64);
            var viewKeyStr = b64Encode(seed2);
            var viewCryptor = createViewCryptor2(viewKeyStr, password);
            return {
                editKeyStr: keyStr, // allows modifying the form as well as answering it.
                viewKeyStr: viewKeyStr, // allows reading the form and answering it.
                signKey: encodeBase64(signKp.secretKey), // allows writing the form
                validateKey: encodeBase64(signKp.publicKey), // allows verifying writing
                cryptKey: viewCryptor.cryptKey, // allows reading the form
                secondaryKey: encodeBase64(secondary), // allows to read answers
                chanId: viewCryptor.chanId,
                secondarySignKey: viewCryptor.secondarySignKey, // allows to  answer forms
                secondaryValidateKey: viewCryptor.secondaryValidateKey // allows verifying of answers
            };
        } catch (err) {
            console.error('[chainpad-crypto.createEditCryptor2] invalid string supplied');
            throw err;
        }
    };

    /* Derive a FileCryptor2 from an optional keyStr and an optional password.
    If there is no keyStr, derive it from a random seed.
    Otherwise, the seed is implicit in the keyStr.
    Derive the cryptKey from the hash of the concatenated password | seed.
    There is no signingKey, as uploaded files are read-only.
    */
    Crypto.createFileCryptor2 = function (keyStr, password) {
        try {
            var seed;
            if (!keyStr) {
                // Generate a keyStr
                seed = Nacl.randomBytes(18);
                keyStr = b64Encode(seed);
            }
            else {
                // We already have an implicit seed in keyStr
                seed = b64Decode(keyStr);
            }

            // Concatenate password and seed to superSeed
            var superSeed = seed;
            if (password) {
                var pwKey = decodeUTF8(password);
                superSeed = new Uint8Array(seed.length + pwKey.length);
                superSeed.set(pwKey);
                superSeed.set(seed, pwKey.length);
            }
            var hash = Nacl.hash(superSeed);
            var chanId = hash.subarray(0,24);
            var cryptKey = hash.subarray(24, 56);
            return {
                fileKeyStr: keyStr, // allows read-only
                cryptKey: cryptKey, // allows read-only
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

    /* Authenticated encryption using a random nonce and shared secret
    Return the concatenated nonce | ciphertext
    */
    Curve.encrypt = function (message, secret) {
        var buffer = decodeUTF8(message);
        var nonce = Nacl.randomBytes(24);
        var box = Nacl.box.after(buffer, nonce, secret);
        return encodeBase64(nonce) + '|' + encodeBase64(box);
    };

    /* Authenticate and decrypt packed of the form nonce|cihertext under the shared secrets
    Return null if authentication fails, otherwise return the plaintext.
    */
    Curve.decrypt = function (packed, secret) {
        var unpacked = packed.split('|');
        var nonce = decodeBase64(unpacked[0]);
        var box = decodeBase64(unpacked[1]);
        var message = Nacl.box.open.after(box, nonce, secret);
        if (message === false) { return null; }
        return encodeUTF8(message);
    };

    /* Encrypt-then-sign (function name is misleading)
    Encrypt msg under the symmetric cryptKey and then sign using signing key.
    Return ciphertext of the form sign(nonce|enc(msg, cryptkey))
    */
    Curve.signAndEncrypt = function (msg, cryptKey, signKey) {
        var packed = Curve.encrypt(msg, cryptKey);
        return encodeBase64(Nacl.sign(decodeUTF8(packed), signKey));
    };

    /* Remove the signature and return the decrypted ciphertext
    We do not verify the signature since this is done by the server (honest-but-curious threat model)
    */
    Curve.openSigned = function (msg, cryptKey /*, validateKey STUBBED*/) {
        var content = decodeBase64(msg).subarray(64);
        return Curve.decrypt(encodeUTF8(content), cryptKey);
    };

    // Derive shared secrets (a symmetric key and a signing key pair) from their public key and my private key
    Curve.deriveKeys = function (theirs, mine) {
        try {
            var pub = decodeBase64(theirs);
            var secret = decodeBase64(mine);

            var sharedSecret = Nacl.box.before(pub, secret);
            var salt = decodeUTF8('CryptPad.signingKeyGenerationSalt');

            // 64 uint8s
            var hash = Nacl.hash(u8_concat([salt, sharedSecret]));
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

    // Provide encrypt/decrypt function for keys derived from their public and my private key
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

Mailbox messages are sent to the server using the WRITE_PRIVATE_MESSAGE API
(https://github.com/xwiki-labs/cryptpad/blob/main/lib/commands/channel.js#L247)
instead of the usual channel message semantics.
The server strips the netflux id of the sender.

This prevents anyonee from correlating which messages came from whom,
but does not limit timing analysis (what messages were sent on which days).
*/

    var u8_slice = function (A, start, end) {
        return new Uint8Array(Array.prototype.slice.call(A, start, end));
    };

    var Mailbox = Crypto.Mailbox = {};

    /* throws on encryption errors
    Return an encrypted message of the form nonce|sender.publicKey|ciphertext
    */
    var asymmetric_encrypt = /* Mailbox.asymmetric_encrypt = */ function (u8_plain, keys) {
        // generate a random nonce
        var u8_nonce = Nacl.randomBytes(Nacl.box.nonceLength);

        // basic asymmetric encryption using named parameters to avoid misuse
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
            keys.my_public, // 32 uint8s
            u8_cipher, // arbitrary length
        ]);

        return u8_bundle;
    };

    /* INTERNAL USE ONLY
     throws on decryption errors

     There are two ways to invoke this function:
     1. by the sender of u8_bundle:
       - the keys must contain keys.their_public (receiver's public key) and keys.my_private (sender's public key)
       - the nonce is extracted from u8_bundle
     2. by the receiver of the message
       - the keys do only need to contain keys.my-private (receiver's public key)
       - the sender's public key is extracted from u8_bundle
       - the nonce is extracted from u8_bundle
     */
    var asymmetric_decrypt = /* Crypto.asymmetric_decrypt = */ function (u8_bundle, keys) {
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
        // depending on how the function is invoked, the public key is taken from a different source
        var u8_plain = Nacl.box.open(
            u8_cipher,
            u8_nonce,
            keys.their_public || u8_sender_public,
            keys.my_private
        );

        if (!u8_plain) { throw new Error('E_DECRYPTION_FAILURE'); }

        // return the ciphertext and sender's public key
        return {
            content: u8_plain,
            author: u8_sender_public,
        };
    };


    // basically acts like an envelope marked only with a delivery address
    var sealSecretLetter = Mailbox.sealSecretLetter = function (plain, keys) {
        // decode string into u8
        var u8_plain = decodeUTF8(plain);

        // encrypt with your permanent private key and the mailbox's public key
        var u8_letter = asymmetric_encrypt(u8_plain, {
            their_public: keys.their_public,
            my_private: keys.my_private,
            my_public: keys.my_public,
        });

        // generate an ephemeral keypair or use the provided one
        var u8_ephemeral_keypair = keys.ephemeral_keypair || Nacl.box.keyPair();

        // seal with an ephemeral key
        var u8_sealed = asymmetric_encrypt(u8_letter, {
            their_public: keys.their_public,
            my_private: u8_ephemeral_keypair.secretKey,
            my_public: u8_ephemeral_keypair.publicKey,
        });

        // if we have a signing key, also sign the message
        // Note that the signing key is symmetric, it thus therefore NOT leake information about the owner.
        if (keys.signingKey) { u8_sealed = Nacl.sign(u8_sealed, keys.signingKey); }

        // return the doubly-encrypted 'envelope' as a base64-encoded string
        return encodeBase64(u8_sealed);
    };

    Mailbox.openOwnSecretLetter = function (b64_bundle, keys) {
        // transform the b64 ciphertext into a Uint8Array
        var u8_bundle = decodeBase64(b64_bundle);

        // If the message is signed, remove the signature
        // NOTE: no need to check the signature, it's already done serverside
        if (keys.validateKey) { u8_bundle = u8_bundle.subarray(64); }

        // open the sealed envelope with your ephemeral private key
        // and throw away the ephemeral key used to seal it
        var letter = asymmetric_decrypt(u8_bundle, {
            my_private: keys.ephemeral_private,
            their_public: keys.their_public
        });

        // read the inner envelope
        var u8_plain = asymmetric_decrypt(letter.content, {
            my_private: keys.my_private,
            their_public: keys.their_public
        });

        // return the content and author
        return {
            content: encodeUTF8(u8_plain.content),
            author: encodeBase64(u8_plain.author),
        };
    };

    // open a secret letter obtained from someone else
    var openSecretLetter = Mailbox.openSecretLetter = function (b64_bundle, keys) {
        // transform the b64 ciphertext into a Uint8Array
        var u8_bundle = decodeBase64(b64_bundle);

        // If the message is signed, remove the signature
        // This can be done since the signature is checked server side
        // --> honest-but-curious threat model
        if (keys.validateKey) { u8_bundle = u8_bundle.subarray(64); }

        // open the sealed envelope with your private key
        // and throw away the ephemeral key used to seal it
        var letter = asymmetric_decrypt(u8_bundle, {
            my_private: keys.my_private,
        });

        // read the internal content, remember its author
        var u8_plain = asymmetric_decrypt(letter.content, {
            my_private: keys.my_private,
        });

        // return the content and author
        return {
            content: encodeUTF8(u8_plain.content),
            author: encodeBase64(u8_plain.author),
        };
    };

    // Provide encryption and decryption functions
    Mailbox.createEncryptor = function (keys) {
        // validate inputs
        if (!keys || typeof(keys) !== 'object') {
            return void console.error("invalid Mailbox.createEncryptor keys");
        }

        ['curvePublic', 'curvePrivate'].forEach(function (k) {
            if (typeof(keys[k]) !== 'string') {
                console.log(k);
                throw new Error("Expected key was not present");
            }
        });

        var u8_my_private = decodeBase64(keys.curvePrivate);
        var u8_my_public = decodeBase64(keys.curvePublic);

        var signingKey = keys.signingKey ? decodeBase64(keys.signingKey) : undefined;
        var validateKey = keys.validateKey ? decodeBase64(keys.validateKey) : undefined;

        return  {
            // returns a base-64 encoded ciphertext bundle
            // or null if decryption failed
            encrypt: function (plain, recipient) {
                // decode the recipient's key
                var u8_their_public = decodeBase64(recipient);

                // prepare an unmarked envelope for them
                // or null if an error is thrown
                try {
                    var sealed = sealSecretLetter(plain, {
                        signingKey: signingKey,
                        ephemeral_keypair: keys.ephemeral_keypair,

                        their_public: u8_their_public,

                        my_private: u8_my_private,
                        my_public: u8_my_public,
                    });
                    // return the base64-encoded ciphertext "envelope"
                    return sealed;
                } catch (e) {
                    console.error(e);
                    return null;
                }
            },
            // return an object with content and author
            // or null if decryption failed
            decrypt: function (cipher) {
                // open a letter from your mailbox
                try {
                    // return { content: UTF8, author: serializedCurve }
                    return openSecretLetter(cipher, {
                         validateKey: validateKey,
                         my_private: u8_my_private,
                    });
                } catch (e) {
                    console.error(e);
                    return null;
                }
            },
        };
    };

/*  Team encryption

Much like mailbox encryption but intended for use cases where:
1. a private signing key is required to write messages to a shared log
2. a private decryption key is required to read messages
3. authorship can be authenticated by those with the private decryption key
4. authorship is unlinkable to anyone without the decryption key

We assume:
1. The private signing key will be distribute to privileged members of a group
2. The private decryption key can be distributed to anyone who should be able to read messages
3. It is safe for anyone to have the public encryption key
4. We may want to allow either:
    * write capabilities without read capabilities
    * read capabilities without write capabilities
5. The public validation key will be transmitted out of band to anyone who needs it

*/

    var Team = Crypto.Team = {};

    var encryptForTeam = function (plain, keys) {
        // sign(curve(curve(msg, author_curve), ephemeral_curve), signing_key)
        var u8_plain = decodeUTF8(plain);

        var u8_inner = asymmetric_encrypt(u8_plain, {
            their_public: keys.team_curve_public,
            my_private: keys.my_curve_private,
            my_public: keys.my_curve_public,
        });

        var u8_ephemeral_keypair = Nacl.box.keyPair();

        var u8_outer = asymmetric_encrypt(u8_inner, {
            their_public: keys.team_curve_public,
            my_private: u8_ephemeral_keypair.secretKey,
            my_public: u8_ephemeral_keypair.publicKey,
        });

        return encodeBase64(Nacl.sign(u8_outer, keys.team_ed_private));
    };

    // INTERNAL USE ONLY
    // throws on decryption or validation errors
    var decryptForTeam = function (b64_bundle, keys, skipValidation) {
        var u8_bundle = decodeBase64(b64_bundle);

        var u8_outer;
        if (skipValidation === true) {
            u8_outer = u8_slice(u8_bundle, 64);
        } else {
            u8_outer = Nacl.sign.open(u8_bundle, keys.team_ed_public);
        }

        if (u8_outer === null) { throw new Error("E_VALIDATION_FAILURE"); }

        // {content: u8, author: u8_curve_public (ephemeral) }
        var inner = asymmetric_decrypt(u8_outer, {
            my_private: keys.team_curve_private,
        });

        // {content: u8, author: u8_curve_public }
        var u8_plain = asymmetric_decrypt(inner.content, {
            my_private: keys.team_curve_private,
        });

        return {
            content: encodeUTF8(u8_plain.content),
            author: encodeBase64(u8_plain.author),
        };
    };

    // external names => internal names
    var team_key_map = {
        teamCurvePublic: 'team_curve_public', // encrypt (to encrypt for)
        teamCurvePrivate: 'team_curve_private', // decrypt (decryption)

        myCurvePublic: 'my_curve_public', // encrypt (authorship inclusion)
        myCurvePrivate: 'my_curve_private', // encrypt (encryption)

        teamEdPublic: 'team_ed_public', // decrypt (validation)
        teamEdPrivate: 'team_ed_private', // encrypt (signing)
    };

    var team_can_decrypt = function (K /* u8_keys */) {
        return Boolean(
            // team_curve_private (to read messages encrypted for the team)
            K.team_curve_private && K.team_curve_private.length === Nacl.box.secretKeyLength &&
            // team_sign_public (to validate that messages are signed by team members)
            K.team_ed_public && K.team_ed_public.length === Nacl.sign.publicKeyLength
        );
    };

    var team_can_encrypt = function (K /* u8_keys */) {
        return Boolean(
            // my_curve_private (for the inner authenticated encryption)
            K.my_curve_private && K.my_curve_private.length === Nacl.box.secretKeyLength &&
            // my_curve_public (for inclusion in the inner message)
            K.my_curve_public && K.my_curve_public.length === Nacl.box.publicKeyLength &&
            // team_curve_public (to encrypt for the team)
            K.team_curve_public && K.team_curve_public.length === Nacl.box.publicKeyLength &&
            // team_ed_private (to sign the final message)
            K.team_ed_private && K.team_ed_private.length === Nacl.sign.secretKeyLength
        );
    };

    var team_validate_own_keys = function (K) {
        return Boolean(
            K.curvePublic && decodeBase64(K.curvePublic).length === Nacl.box.publicKeyLength &&
            K.curvePrivate && decodeBase64(K.curvePrivate).length === Nacl.box.secretKeyLength
        );
    };

    var u8_stretch = function (u8) {
        var hashed = Nacl.hash(u8);
        return [
            u8_slice(hashed, 0, 32),
            u8_slice(hashed, 32)
        ];
    };

    var merge = function (o1, o2) {
        var o3 = JSON.parse(JSON.stringify(o1));
        Object.keys(o2).forEach(function (k) {
            o3[k] = o2[k];
        });
        return o3;
    };

    var u8_deriveGuestKeys = function (u8_seed2) {
        // channel, team_curve_private, team_curve_public
        var stretched = u8_stretch(u8_seed2);

        var teamCurve = Nacl.box.keyPair.fromSecretKey(stretched[0]);
        var u8_channel = u8_slice(stretched[1], 0, 16);

        return {
            channel: encodeHex(u8_channel),
            teamCurvePublic: encodeBase64(teamCurve.publicKey),
            teamCurvePrivate: encodeBase64(teamCurve.secretKey),
            viewKeyStr: Crypto.b64RemoveSlashes(encodeBase64(u8_seed2)),
        };
    };

    Team.deriveGuestKeys = function (seed2) {
        return u8_deriveGuestKeys(decodeBase64(Crypto.b64AddSlashes(seed2)));
    };

    Team.createSeed = function () {
        return Crypto.b64AddSlashes(encodeBase64(Nacl.randomBytes(18)));
    };

    Team.deriveMemberKeys = function (seed1, myKeys) {
        var u8_seed1;
        try {
            u8_seed1 = decodeBase64(Crypto.b64AddSlashes(seed1));
            if (u8_seed1.length < 18) { throw new Error("INVALID_SEED"); }
        } catch (err) {
            throw err;
        }

        // my_keys => {myCurvePublic, myCurvePrivate}
        if (!team_validate_own_keys(myKeys)) { throw new Error('INVALID_OWN_KEYS'); }

        var stretched = u8_stretch(u8_seed1);

        // team_ed_private, team_ed_public (distributed via historyKeeper)
        var teamEd = Nacl.sign.keyPair.fromSeed(stretched[0]);

        // channel, team_curve_private, team_curve_public
        var guestKeys = u8_deriveGuestKeys(stretched[1]);

        return merge({
            // your keys myCurvePublic, myCurvePrivate
            myCurvePublic: myKeys.curvePublic,
            myCurvePrivate: myKeys.curvePrivate,
            // member keys (teamEdPrivate, teamEdPublic)
            teamEdPrivate: encodeBase64(teamEd.secretKey),
            teamEdPublic: encodeBase64(teamEd.publicKey),
        }, guestKeys); // guest keys & info (channel, teamCurvePrivate, teamCurvePublic)
    };

    // returns an object
    // any of: {encrypt}, {decrypt}, {encrypt, decrypt}
    // throws if it is impossible to correctly create either method
    // encrypt and decrypt take strings as input
    // both log and return null in the event of internal errors
    // decrypt can optionally skip validation if you trust the source of the message
    Team.createEncryptor = function (keys) {
        var u8_keys = {};
        Object.keys(team_key_map).forEach(function (k) {
            if (!keys[k]) { return; }
            try {
                u8_keys[team_key_map[k]] = decodeBase64(keys[k]);
            } catch (err) {
                console.log(k);
                throw new Error('INVALID_KEY_SUPPLIED');
            }
        });

        var out = {};

        if (team_can_encrypt(u8_keys)) {
            // (utf8_string) => base64_string || null
            out.encrypt = function (plain) {
                try {
                    return encryptForTeam(plain, u8_keys);
                } catch (e) {
                    console.error(e);
                    return null;
                }
            };
        }

        if (team_can_decrypt(u8_keys)) {
            // (base64_string, skip_validation_bool) => {content: utf8_string, author: base64_string} || null
            out.decrypt = function (cipher, skipValidation) {
                try {
                    return decryptForTeam(cipher, u8_keys, skipValidation);
                } catch (e) {
                    console.error(e);
                    return null;
                }
            };
        }

        if (Object.keys(out).length === 0) { throw new Error("INVALID_TEAM_CONFIGURATION"); }

        return out;
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
        window.chainpad_crypto = factory(window.nacl);
    }
}());
