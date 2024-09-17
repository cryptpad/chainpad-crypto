var Crypto = require("../crypto");
var Nacl = require("tweetnacl");
var test = require('tape'); 

test('Test basic one to one curve encryption', function (t) {
    var Alice = Nacl.box.keyPair();
    var Alice_public = Nacl.util.encodeBase64(Alice.publicKey);

    var Bob = Nacl.box.keyPair();
    var Bob_public = Nacl.util.encodeBase64(Bob.publicKey);

    var Curve = Crypto.Curve;

    // Basic one to one curve encryption used in CryptPad's chat

    // Alice and Bob can use their own private keys and the other's public key
    // to derive some shared values for their pairwise-encrypted channel
    // that includes a pre-computed secret key for curve encryption, a signing key, and a validate key

    // Alice derives the keys
    var Alice_set = Curve.deriveKeys(Bob_public, Nacl.util.encodeBase64(Alice.secretKey));

    // Bob does the same
    var Bob_set = Curve.deriveKeys(Alice_public, Nacl.util.encodeBase64(Bob.secretKey));

    ['cryptKey', 'signKey', 'validateKey'].forEach(function (k) {
        // these should all be strings
        t.equal('string', typeof(Alice_set[k]));
        t.equal('string', typeof(Bob_set[k]));

        // and Alice and Bob should have exactly the same values
        t.equal(Alice_set[k], Bob_set[k]);
    });

    var Alice_cryptor = Curve.createEncryptor(Alice_set);
    var Bob_cryptor = Curve.createEncryptor(Bob_set);

    // Now Alice should be able to send Bob a message

    var message = 'pewpewpew';

    var Alice_ciphertext = Alice_cryptor.encrypt(message);

    var Bob_plaintext = Bob_cryptor.decrypt(Alice_ciphertext);

    t.equal(message, Bob_plaintext);
    t.end();
});

