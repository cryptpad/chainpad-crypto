var Crypto = require("../crypto");
var Nacl = require("tweetnacl");
var test = require('tape'); 

var Alice = Nacl.box.keyPair();
var Alice_public = Nacl.util.encodeBase64(Alice.publicKey);

var Bob = Nacl.box.keyPair();
var Bob_public = Nacl.util.encodeBase64(Bob.publicKey);

var Curve = Crypto.Curve;

test('Test basic Mailbox encryption with openOwnSecretLetter', function (t) {
    // Alice wants to send a letter to Bob, but she wants to read it later.
    var message = "It is a short test.";

    var keys = {
        my_private: Alice.secretKey,
        my_public: Alice.publicKey,
        their_public : Bob.publicKey,
        ephemeral_keypair : Nacl.box.keyPair(),
    };
    keys.ephemeral_private = keys.ephemeral_keypair.secretKey;
    keys.ephemeral_public = keys.ephemeral_keypair.publicKey;

    // Encrypt
    var envelope = Crypto.Mailbox.sealSecretLetter(message, keys);
    // Decrypt
    var letter = Crypto.Mailbox.openOwnSecretLetter(envelope, keys);

    t.equal(message, letter.content, "Can decrypt own content");
    t.equal(Alice_public, letter.author, "Author of own letter is correct");

    t.end();
});


test('Test basic Mailbox encryption', function (t) {
    var message = "test";

    // Encrypt
    var envelope = Crypto.Mailbox.sealSecretLetter(message, {
        their_public: Alice.publicKey,

        my_private: Bob.secretKey,
        my_public: Bob.publicKey,
    });
    // Decrypt
    var letter = Crypto.Mailbox.openSecretLetter(envelope, {
        my_private: Alice.secretKey,
    });

    t.equal(message, letter.content, "Can decrypt own content");
    t.equal(Bob_public, letter.author, "Author of own letter is correct");

    t.end();
});

test('Test basic Mailbox using createEncryptor', function (t) {
    // Bob wants to drop a letter in Alice' mailbox.

    // Bob creates an encryptor with his base64-encoded private key
    var bob_cryptor = Crypto.Mailbox.createEncryptor({
        curvePrivate: Nacl.util.encodeBase64(Bob.secretKey),
        curvePublic: Nacl.util.encodeBase64(Bob.publicKey),
    });

    // Bob writes his very important letter
    var bob_plaintext = "pewpewpew bangbangbang";

    var bob_ciphertext = bob_cryptor.encrypt(
        bob_plaintext,
        Alice_public // encrypt for Alice' base64-encoded public key
    );

    t.assert(Boolean(bob_ciphertext));
    t.equal('string', typeof(bob_ciphertext));

    // Alice checks her mailbox
    var Alice_cryptor = Crypto.Mailbox.createEncryptor({
        curvePrivate: Nacl.util.encodeBase64(Alice.secretKey),
        curvePublic: Nacl.util.encodeBase64(Alice.publicKey),
    });

    var alice_plaintext = Alice_cryptor.decrypt(bob_ciphertext);

    t.assert(Boolean(alice_plaintext));
    t.equal('object', typeof(alice_plaintext));

    t.equal(bob_plaintext, alice_plaintext.content, "Alice and Bob decrypt to the same message");

    t.end();

});
