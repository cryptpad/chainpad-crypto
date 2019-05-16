var Assert = require("assert");
var Crypto = require("./crypto");
var Nacl = require("tweetnacl");

var Alice = Nacl.box.keyPair();
var Alice_public = Nacl.util.encodeBase64(Alice.publicKey);

var Bob = Nacl.box.keyPair();
var Bob_public = Nacl.util.encodeBase64(Bob.publicKey);

/*
(function () {
    // validate internal methods

    var message = "bang bang bang";
    message = "x";
    var u8_message = Nacl.util.decodeUTF8(message);

    // bob does an asymmetric encryption for alice

    var bob_cipher = Crypto._.asymmetric_encrypt(u8_message, {
        their_public: Alice.publicKey,
        my_public: Bob.publicKey,
        my_private: Bob.secretKey,
    });

    var decrypted = Crypto._.asymmetric_decrypt(bob_cipher, {
        my_private: Alice.secretKey,
    });

    //console.log(decrypted);

    Assert(Boolean(decrypted));
    Assert.equal(Nacl.util.encodeUTF8(decrypted.content), message);
}());
*/

(function () {
    var message = "test";
    var envelope = Crypto.Mailbox.sealSecretLetter(message, {
        their_public: Alice.publicKey,

        my_private: Bob.secretKey,
        my_public: Bob.publicKey,
    });
    var letter = Crypto.Mailbox.openSecretLetter(envelope, {
        my_private: Alice.secretKey,
    });
    Assert.equal(message, letter.content);
    Assert.equal(Bob_public, letter.author);
}());


(function () {
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

    Assert(Boolean(bob_ciphertext));
    Assert.equal('string', typeof(bob_ciphertext));

    // Alice checks her mailbox
    var Alice_cryptor = Crypto.Mailbox.createEncryptor({
        curvePrivate: Nacl.util.encodeBase64(Alice.secretKey),
        curvePublic: Nacl.util.encodeBase64(Alice.publicKey),
    });

    var alice_plaintext = Alice_cryptor.decrypt(bob_ciphertext);
    //console.log(alice_plaintext);

    Assert(Boolean(alice_plaintext));
    Assert.equal('object', typeof(alice_plaintext));

    Assert.equal(bob_plaintext, alice_plaintext.content);
}());
