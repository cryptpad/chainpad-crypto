var Crypto = require("../crypto");
var Nacl = require("tweetnacl");
var test = require('tape'); 

test('Test FileCryptor2 without passwords', function (t) {
    var message = "FileCryptor2";
    var alice_cryptor = Crypto.createFileCryptor2(void 0, void 0);
    var bob_cryptor = Crypto.createFileCryptor2(alice_cryptor.fileKeyStr, void 0);
    var charlie_cryptor = Crypto.createFileCryptor2("abcd", void 0);

    t.deepEqual(alice_cryptor, bob_cryptor, "Generate the same keys");

    t.deepEqual(alice_cryptor, bob_cryptor);
    ["fileKeyStr", "cryptKey", "chanId"].forEach(function (k) {
        t.notDeepEqual(alice_cryptor[k], charlie_cryptor[k], "Different keys under wrong keystr");
    });
    t.end();
});


test('Test FileCryptor2 with passwords', function (t) {
    var message = "FileCryptor2";
    var password = "SuperSecretPassword";
    var alice_cryptor = Crypto.createFileCryptor2(void 0, password);
    var bob_cryptor = Crypto.createFileCryptor2(alice_cryptor.fileKeyStr, password );
    var charlie_cryptor = Crypto.createFileCryptor2(alice_cryptor.fileKeyStr, "wrong" );
    var diana_cryptor = Crypto.createFileCryptor2("abcd", password);
    t.deepEqual(alice_cryptor, bob_cryptor, "Generate the same keys");
    ['cryptKey', "chanId"].forEach(function (k) {
        // Alice and Charlie should NOT generate the same keys (wrong password)
        t.notDeepEqual(alice_cryptor[k], charlie_cryptor[k], "Different keys under wrong password");
        // Alice and Charlie should NOT generate the same keys (wrong password)
        t.notDeepEqual(alice_cryptor[k], diana_cryptor[k], "Different keys under wrong keystr");
    });
    t.end();
});
