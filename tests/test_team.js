var Crypto = require("../crypto");
var Nacl = require("tweetnacl");
var test = require('tape'); 


//Helper functions
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


var Alice = Nacl.box.keyPair();
var Alice_public = Nacl.util.encodeBase64(Alice.publicKey);

var Bob = Nacl.box.keyPair();
var Bob_public = Nacl.util.encodeBase64(Bob.publicKey);
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

// Bob has the keys to read, but not write
var bob = makeCurveKeys();
bob.cryptor = Team.createEncryptor({
    teamCurvePrivate: team.curve.private,
    teamEdPublic: team.ed.public,
});


var plaintext = 'PEWPEWPEW';

var alice_ciphertext = alice.cryptor.encrypt(plaintext);

test('Test Mailbox with validation', function (t) {
    t.assert(Boolean(alice.cryptor.encrypt));
    t.assert(Boolean(alice.cryptor.decrypt));


    t.assert(alice_ciphertext);

    t.assert(bob.cryptor.decrypt, "Bob can decrypt");
    t.assert(!bob.cryptor.encrypt, "Bob can NOT encrypt");

    var bob_decrypted = bob.cryptor.decrypt(alice_ciphertext);

    t.equal(bob_decrypted.content, plaintext, "Bob correctly decrypts");
    t.equal(bob_decrypted.author, alice.public, "Bob sees author");

    t.end();
});

test('Test Mailbox without validation', function (t) {
    // the same thing as above, but skipping validation
    bob_decrypted = bob.cryptor.decrypt(alice_ciphertext, true);

    t.equal(bob_decrypted.content, plaintext, "Bob correctly decrypts w/o validation");
    t.equal(bob_decrypted.author, alice.public, "Bob correctly decrypts author w/o validation");

    t.end();
});

test('Test Mailbox write only', function (t) {
    // Chuck has the keys to write, but not read
    var chuck = makeCurveKeys();
    chuck.cryptor = Team.createEncryptor({
        myCurvePrivate: chuck.private,
        myCurvePublic: chuck.public,
        teamCurvePublic: team.curve.public,
        teamEdPrivate: team.ed.private,
    });
    t.assert(chuck.cryptor.encrypt, "Chuck can encrypt");
    t.assert(!chuck.cryptor.decrypt, "Chuck cannot decrypt");

    var plaintext = 'PEZPEZ';
    var chuck_ciphertext = chuck.cryptor.encrypt(plaintext);

    var alice_decrypted = alice.cryptor.decrypt(chuck_ciphertext);

    t.equal(alice_decrypted.content, plaintext, "Alice can decrypt content");
    t.equal(alice_decrypted.author, chuck.public, "Alice can decrpyt author");

    t.end();
});

test('Test Mailbox read only', function (t) {
    // Diana has the keys to read, but not write
    var diana = makeCurveKeys();
    diana.cryptor = Team.createEncryptor({
        myCurvePrivate: diana.private,
        myCurvePublic: diana.public,
        teamCurvePrivate: team.curve.private,
        teamEdPublic: team.ed.public,
    });
    t.assert(!diana.cryptor.encrypt, "Diana cannot encrypt");
    t.assert(diana.cryptor.decrypt, "Diana can decrypt");

    var plaintext = 'a boring plaintext';
    var alice_ciphertext = alice.cryptor.encrypt(plaintext);

    var diana_decrypted = diana.cryptor.decrypt(alice_ciphertext);

    t.equal(diana_decrypted.content, plaintext, "Diana can decrypt content");
    t.equal(diana_decrypted.author, alice.public, "Diana can decrypt author");

    t.end();
});
