var octokey = octokey || {};

octokey.privateKey = function (raw_private_key) {

    var _public = {},
        private_key = null,
        decrypt_key = null, // function: passphrase -> private key
        passphrase_timeout = 5 * 60 * 1000, // 5 minutes in milliseconds
        passphrase_timer = null;

    // This matches the logic in OpenSSL's crypto/pem/pem_lib.c
    if (raw_private_key.match(/-----BEGIN RSA PRIVATE KEY-----/)) {
        // Unencrypted PEM, or encrypted key in OpenSSL 'traditional' format.
        var key_parts = raw_private_key.match(/-----BEGIN [^\n]+-----((?:(?:\n[^\n]+:[^\n]*)*\n\s*\n)?)([A-Za-z0-9+\/=\s]+)-----END [^\n]+-----/);
        if (!key_parts) {
            throw 'the RSA private key file has an invalid structure';
        }
        var headers = key_parts[1].trim(), data = forge.util.createBuffer(forge.util.decode64(key_parts[2]));

        // The header format parsing is very strict in OpenSSL's PEM_get_EVP_CIPHER_INFO
        // (e.g. reordering of headers is not allowed, case sensitive).
        var cipher_info = headers.match(/Proc-Type: 4,ENCRYPTED\s*DEK-Info: ([A-Z0-9\-]*),([0-9A-Fa-f]+)/);
        if (cipher_info) {
            var init_vector = forge.util.hexToBytes(cipher_info[2]);
            var cipher = {
                'AES-128-CBC':  {algorithm: forge.aes, key_length: 16},
                'DES-EDE3-CBC': {algorithm: forge.des, key_length: 24}
            }[cipher_info[1]];

            if (!cipher) {
                throw 'unsupported private key encryption cipher: ' + cipher_info[1];
            }

            decrypt_key = function (passphrase) {
                // The following algorithm for deriving the key is hard-coded in OpenSSL
                // in EVP_BytesToKey (crypto/evp/evp_key.c) and PEM_do_header (crypto/pem/pem_lib.c)
                var key = new forge.util.ByteBuffer(), digest = '';
                while (key.length() < cipher.key_length) {
                    var md = forge.md.md5.create();
                    md.update(digest);
                    md.update(passphrase, 'utf-8');
                    md.update(init_vector.substr(0, 8)); // the first PKCS5_SALT_LEN (8) bytes of IV are used as salt
                    digest = md.digest().getBytes();
                    key.putBytes(digest.substr(0, cipher.key_length - key.length()));
                }

                var decrypt = cipher.algorithm.startDecrypting(key, forge.util.createBuffer(init_vector));
                decrypt.update(data);
                decrypt.finish();
                try {
                    return forge.pki.privateKeyFromAsn1(forge.asn1.fromDer(decrypt.output));
                } catch(error) {
                    return false;
                }
            };

        } else {
            // No headers indicating that the key is encrypted
            private_key = forge.pki.privateKeyFromPem(raw_private_key);
        }

    } else if (raw_private_key.match(/-----BEGIN ENCRYPTED PRIVATE KEY-----/)) {
        // Encrypted PKCS8, supported directly by Forge
        decrypt_key = function (passphrase) {
            return forge.pki.decryptRsaPrivateKey(raw_private_key, passphrase);
        };

    } else if (raw_private_key.match(/-----BEGIN PRIVATE KEY-----/)) {
        // TODO unencrypted PKCS8

    } else {
        var keytype = raw_private_key.match(/-----BEGIN ([^\n]+) PRIVATE KEY-----/);
        if (keytype && keytype[1]) {
            throw keytype[1] + ' private keys are not supported';
        } else {
            throw 'unrecognised private key format';
        }
    }

    _public.passphrase_required = !private_key;

    // Decrypts the private key using a given passphrase; returns true on success,
    // false if the passphrase is incorrect. The decrypted key is held in this
    // object for 5 minutes, and then discarded.
    _public.setPassphrase = function (passphrase) {
        if (!decrypt_key) {
            return true;
        }

        private_key = decrypt_key(passphrase);
        _public.passphrase_required = !private_key;

        if (passphrase_timer) {
            window.clearTimeout(passphrase_timer);
            passphrase_timer = null;
        }
        if (!private_key) {
            return false;
        }

        passphrase_timer = window.setTimeout(function () {
            private_key = null;
            _public.passphrase_required = true;
        }, passphrase_timeout);

        return true;
    };


    /* Extracts the public key from the private key object. Only available while the
     * private key is unlocked. */
    _public.publicKey = function () {
        return private_key ? octokey.publicKey(private_key.e, private_key.n) : null;
    };

    /* Takes a binary string and performs RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature)
     * with SHA1, as defined in RFC3447, and as used in SSH as described in RFC4253.
     * Returns a binary string consisting of an algorithm identifier and the signature. */
    _public.sign = function (data) {
        if (!private_key) {
            return null;
        }

        var digest = forge.md.sha1.create();
        digest.update(data);

        var buf = new forge.util.ByteBuffer();
        buf.putBinaryString('ssh-rsa');
        buf.putBinaryString(private_key.sign(digest));
        return buf.data;
    };

    return _public;
};
