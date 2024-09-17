
var Crypto = require("../crypto");
var Nacl = require("tweetnacl");
var test = require('tape'); 

// We first need to generate a viewKeystr.
var editcryptor = Crypto.createEditCryptor2(void 0, void 0, void 0);
var other_editcryptor = Crypto.createEditCryptor2(void 0, void 0, void 0);

test('Test ViewCryptor2 without passwords', function (t) {
    var message = "Hello ViewCryptor2";
    var alice_cryptor = Crypto.createViewCryptor2(editcryptor.viewKeyStr, void 0);
    var bob_cryptor = Crypto.createViewCryptor2(editcryptor.viewKeyStr, void 0);
    var charlie_cryptor = Crypto.createViewCryptor2(other_editcryptor.viewKeyStr, void 0);

    t.deepEqual(alice_cryptor, bob_cryptor, "Generate the same keys");

    t.deepEqual(alice_cryptor, bob_cryptor);
    ["viewKeyStr", "cryptKey", "chanId"].forEach(function (k) {
        t.notDeepEqual(alice_cryptor[k], charlie_cryptor[k], "Different keys under wrong keystr");
    });
    t.end();
});


test('Test ViewCryptor2 with passwords', function (t) {
    var message = "FileCryptor2";
    var password = "SuperSecretPassword";
    var alice_cryptor = Crypto.createViewCryptor2(editcryptor.viewKeyStr, password);
    var bob_cryptor = Crypto.createViewCryptor2(editcryptor.viewKeyStr, password);
    var charlie_cryptor = Crypto.createViewCryptor2(editcryptor.viewKeyStr, "wrong password");
    var diana_cryptor = Crypto.createViewCryptor2(other_editcryptor.viewKeyStr, password);
    t.deepEqual(alice_cryptor, bob_cryptor, "Generate the same keys");
    ['cryptKey', "chanId", "secondarySignKey", "secondaryValidateKey"].forEach(function (k) {
        // Alice and Charlie should NOT generate the same keys (wrong password)
        t.notDeepEqual(alice_cryptor[k], charlie_cryptor[k], "Different keys under wrong password");
        // Alice and Charlie should NOT generate the same keys (wrong password)
        t.notDeepEqual(alice_cryptor[k], diana_cryptor[k], "Different keys under wrong keystr");
    });
    t.end();
});
