var Crypto = require("../crypto");
var Nacl = require("tweetnacl");
var test = require('tape'); 

// EditCryptor2
test('Test EditCryptor2 without passwords', function (t) {
    t.pass("passed");
    var message = "EditCryptor2";
    var alice_cryptor = Crypto.createEditCryptor2(void 0, void 0, void 0);
    var bob_cryptor = Crypto.createEditCryptor2(alice_cryptor.editKeyStr, void 0, void 0 );
    var charlie_cryptor = Crypto.createEditCryptor2("abcd", void 0, void 0);

    // Alice and Bob should generate the same keys
    t.deepEqual(alice_cryptor, bob_cryptor);
    ['cryptKey', "chanId"].forEach(function (k) {
        t.notDeepEqual(alice_cryptor[k], charlie_cryptor[k], "Do NOT generate the same keys under wrong keystr");
    });
    t.end();
});

test('Test EditCryptor2 with passwords', function (t) {
    t.pass("passed");
    var message = "EditCryptor2";
    var password = "SuperSecretPassword";
    var alice_cryptor = Crypto.createEditCryptor2(void 0, void 0, password);
    var bob_cryptor = Crypto.createEditCryptor2(alice_cryptor.editKeyStr, void 0, password );
    var charlie_cryptor = Crypto.createEditCryptor2(alice_cryptor.editKeyStr, void 0,  "Wrong" );
    var diana_cryptor = Crypto.createEditCryptor2("abcd", void 0, password);

    // Alice and Bob should generate the same keys
    t.deepEqual(alice_cryptor, bob_cryptor);
    ['cryptKey', "chanId"].forEach(function (k) {
        t.notEqual(alice_cryptor[k], diana_cryptor[k], "Do NOT generate the same keys under wrong keystr"); 
    });
    t.end();
});

