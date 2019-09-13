var Assert = require("assert");
var Crypto = require("./crypto");
var Nacl = require("tweetnacl");

// encrypt
// decrypt
// parseKey
// rand64
// genKey
// b64RemoveSlashes
// b64AddSlashes
// createEncryptor
// createEditCryptor
// createViewCryptor
// createViewCryptor2
// createEditCryptor2
// createFileCryptor2
// Curve
    // encrypt
    // decrypt
    // signAndEncrypt
    // openSigned
    // deriveKeys
    // createEncryptor
// [ ] Mailbox
    // [ ] sealSecretLetter
    // [ ] openSecretLetter
    // [ ] createEncryptor

var Alice = Nacl.box.keyPair();
var Alice_public = Nacl.util.encodeBase64(Alice.publicKey);

var Bob = Nacl.box.keyPair();
var Bob_public = Nacl.util.encodeBase64(Bob.publicKey);

(function  () {
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
    Assert.equal('string', typeof(Alice_set[k]));
    Assert.equal('string', typeof(Bob_set[k]));

    // and Alice and Bob should have exactly the same values
    Assert.equal(Alice_set[k], Bob_set[k]);
});

var Alice_cryptor = Curve.createEncryptor(Alice_set);
var Bob_cryptor = Curve.createEncryptor(Bob_set);

// Now Alice should be able to send Bob a message

var message = 'pewpewpew';

var Alice_ciphertext = Alice_cryptor.encrypt(message);

var Bob_plaintext = Bob_cryptor.decrypt(Alice_ciphertext);

Assert.equal(message, Bob_plaintext);
}());

// Mailbox stuff

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

    Assert(Boolean(alice_plaintext));
    Assert.equal('object', typeof(alice_plaintext));

    Assert.equal(bob_plaintext, alice_plaintext.content);
}());

var encode64 = Nacl.util.encodeBase64;

var makeCurveKeys = function () {
    var pair = Nacl.box.keyPair();
    return {
        public: encode64(pair.publicKey),
        private: encode64(pair.secretKey),
    };
};

var makeEdKeys = function () {
    var pair = Nacl.sign.keyPair();
    return {
        public: encode64(pair.publicKey),
        private: encode64(pair.secretKey),
    };
};

(function () {
    var Team = Crypto.Team;

    var team = {
        ed: makeEdKeys(),
        curve: makeCurveKeys(),
    };

    // Alice has all the keys for a team
    var alice = makeCurveKeys();
    alice.cryptor = Team.createEncryptor({
        teamCurvePublic: team.curve.public,
        teamCurvePrivate: team.curve.private,

        teamEdPublic: team.ed.public,
        teamEdPrivate: team.ed.private,

        myCurvePublic: alice.public,
        myCurvePrivate: alice.private,
    });

    Assert(Boolean(alice.cryptor.encrypt));
    Assert(Boolean(alice.cryptor.decrypt));

    var plain = 'PEWPEWPEW';

    var alice_ciphertext = alice.cryptor.encrypt(plain);
    Assert(alice_ciphertext);

    // Bob has the keys to read, but not write
    var bob = makeCurveKeys();
    bob.cryptor = Team.createEncryptor({
        teamCurvePrivate: team.curve.private,
        teamEdPublic: team.ed.public,
    });

    Assert(bob.cryptor.decrypt); // Bob can decrypt
    Assert(!bob.cryptor.encrypt); // Bob can't encrypt

    var bob_decrypted = bob.cryptor.decrypt(alice_ciphertext);

    Assert.equal(bob_decrypted.content, plain);
    Assert.equal(bob_decrypted.author, alice.public);

    // the same thing, but skipping validation
    bob_decrypted = bob.cryptor.decrypt(alice_ciphertext, true);

    Assert.equal(bob_decrypted.content, plain);
    Assert.equal(bob_decrypted.author, alice.public);

    // Chuck has the keys to write, but not read
    var chuck = makeCurveKeys();
    chuck.cryptor = Team.createEncryptor({
        myCurvePrivate: chuck.private,
        myCurvePublic: chuck.public,
        teamCurvePublic: team.curve.public,
        teamEdPrivate: team.ed.private,
    });

    Assert(chuck.cryptor.encrypt);
    Assert(!chuck.cryptor.decrypt);

    var plain2 = 'PEZPEZ';
    var chuck_ciphertext = chuck.cryptor.encrypt(plain2);

    var alice_decrypted = alice.cryptor.decrypt(chuck_ciphertext);

    Assert.equal(alice_decrypted.content, plain2);
    Assert.equal(alice_decrypted.author, chuck.public);
}());
