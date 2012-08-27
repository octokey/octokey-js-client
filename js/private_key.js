var octokey = octokey || {};

octokey.privateKey = function (private_key_pem) {

    var _public = {},
        private_key = null,
        passphrase_timeout = 5 * 60 * 1000, // 5 minutes in milliseconds
        passphrase_timer = null;

    // Only support PKCS8-encoded keys here, to discourage people from using the less secure
    // 'traditional' SSH key format. octokey.privateKey.convert can perform the conversion.
    if (private_key_pem.match(/-----BEGIN PRIVATE KEY-----/)) {
        // Unencrypted PKCS8
        private_key = forge.pki.privateKeyFromPem(private_key_pem);
    } else if (!private_key_pem.match(/-----BEGIN ENCRYPTED PRIVATE KEY-----/)) {
        throw 'Unsupported private key type. Please use octoKey.privateKey.convert to convert it';
    }

    _public.passphrase_required = !private_key;

    // Decrypts the private key using a given passphrase; returns true on success,
    // false if the passphrase is incorrect. The decrypted key is held in this
    // object for 5 minutes, and then discarded.
    _public.setPassphrase = function (passphrase) {
        // Ignore passphrase if the key wasn't encrypted in the first place
        if (private_key && !passphrase_timer) {
            return true;
        }

        try {
            private_key = forge.pki.decryptRsaPrivateKey(private_key_pem, passphrase);
        } catch (error) {
            console.log(error); // FIXME
            return false;
        }
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


// Takes a private key in any supported format (currently either PKCS#8 PEM or the SSH 'traditional'
// private key format) and converts it into a consistent PKCS#8 PEM format. If one passphrase is
// given, it is used both for decrypting the input and for encrypting the output. If two passphrases
// are given, the first is used for decrypting and the second is used for encrypting. (This allows
// you to to change the passphrase for a key.) If the output passphase is empty, the output is
// unencrypted.
//
// Returns an object with properties:
//   * pem: The converted private key PEM string, or null if conversion failed
//   * errors: Array of errors that occurred during conversion (null if successful)
octokey.privateKey.convert = function (input_pem, input_passphrase, output_passphrase) {

    // Encryption options for the output key
    var output_options = {
        encAlg: 'aes128',

        // Iteration count -- the higher, the harder it is to brute-force the passphrase. OpenSSL
        // uses 2048. This takes about 700ms in Chrome 21's JS engine on an Intel Core 2 Duo laptop.
        // TODO benchmark this on more browsers & CPUs.
        count: 2048,

        // 128 bits of salt, twice the minimum recommended by PBKDF2 (RFC 2898) -- superstitiously
        // making it bigger because I'm unsure of the quality of entropy we can get from the
        // browser. Though hash crackers are so fast these days that size of salt doesn't make too
        // much of a difference anyway.
        saltSize: 16
    };

    var private_key = null;
    if (typeof output_passphrase === 'undefined') {
        output_passphrase = input_passphrase;
    }

    function error(message) {
        return {pem: null, errors: [message]};
    }

    // This matches the logic in OpenSSL's crypto/pem/pem_lib.c
    if (input_pem.match(/-----BEGIN RSA PRIVATE KEY-----/)) {

        // Unencrypted PEM, or encrypted key in OpenSSL 'traditional' format.
        var key_parts = input_pem.match(/-----BEGIN [^\n]+-----((?:(?:\s*\n[^\n]+:[^\n]*)*\n\s*\n)?)([A-Za-z0-9+\/=\s]+)-----END [^\n]+-----/);
        if (!key_parts) {
            return error('the RSA private key file has an invalid structure');
        }
        var headers = key_parts[1].trim(), data = forge.util.createBuffer(forge.util.decode64(key_parts[2]));

        // The header format parsing is very strict in OpenSSL's PEM_get_EVP_CIPHER_INFO
        // (headers cannot be reordered, added or removed; and the parsing is case sensitive).
        var cipher_info = headers.match(/Proc-Type: 4,ENCRYPTED\s*DEK-Info: ([A-Z0-9\-]*),([0-9A-Fa-f]+)/);
        if (cipher_info) {
            var init_vector = forge.util.hexToBytes(cipher_info[2]);
            var cipher = {
                'AES-128-CBC':  {algorithm: forge.aes, key_length: 16},
                'DES-EDE3-CBC': {algorithm: forge.des, key_length: 24}
            }[cipher_info[1]];

            if (!cipher) {
                return error('unsupported private key encryption cipher: ' + cipher_info[1]);
            }
            if (!input_passphrase) {
                return error('input passphrase required');
            }

            // The following algorithm for deriving the key is hard-coded in OpenSSL
            // in EVP_BytesToKey (crypto/evp/evp_key.c) and PEM_do_header (crypto/pem/pem_lib.c)
            var key = new forge.util.ByteBuffer(), digest = '';
            while (key.length() < cipher.key_length) {
                var md = forge.md.md5.create();
                md.update(digest);
                md.update(input_passphrase, 'utf-8');
                md.update(init_vector.substr(0, 8)); // the first PKCS5_SALT_LEN (8) bytes of IV are used as salt
                digest = md.digest().getBytes();
                key.putBytes(digest.substr(0, cipher.key_length - key.length()));
            }

            var decrypt = cipher.algorithm.startDecrypting(key, forge.util.createBuffer(init_vector));
            decrypt.update(data);
            decrypt.finish();

            // The most likely effect of an incorrect passphrase is that the decrypted string is not
            // valid DER; but it could also be valid DER but not the right kind of ASN.1 structure.
            var asn1;
            try {
                private_key = forge.pki.privateKeyFromAsn1(forge.asn1.fromDer(decrypt.output));
            } catch (e) {
                var message = (typeof(e) === 'object' ? e.message : e);
                return {pem: null, errors: ['incorrect input passphrase', message]};
            }

        } else {
            // No headers indicating that the key is encrypted
            private_key = forge.pki.privateKeyFromPem(input_pem);
        }

    } else if (input_pem.match(/-----BEGIN ENCRYPTED PRIVATE KEY-----/)) {
        // Encrypted PKCS8, supported directly by Forge
        if (!input_passphrase) {
            return error('input passphrase required');
        }
        try {
            private_key = forge.pki.decryptRsaPrivateKey(input_pem, input_passphrase);
        } catch (e) {
            return error(typeof(e) === 'object' ? e.message : e);
        }
        if (!private_key) {
            return error('incorrect input passphrase');
        }

    } else if (input_pem.match(/-----BEGIN PRIVATE KEY-----/)) {
        // Unencrypted PKCS8
        try {
            private_key = forge.pki.privateKeyFromPem(input_pem);
        } catch (e) {
            return error(typeof(e) === 'object' ? e.message : e);
        }

    } else {
        var keytype = input_pem.match(/-----BEGIN ([^\n]+) PRIVATE KEY-----/);
        if (keytype && keytype[1]) {
            return error(keytype[1] + ' private keys are not supported');
        } else {
            return error('unrecognised private key format');
        }
    }

    var output_pem;
    if (output_passphrase) {
        // Generate PKCS#8 output
        output_pem = forge.pki.encryptRsaPrivateKey(private_key, output_passphrase, output_options);
    } else {
        // Unencrypted key :( not sure if we should even allow this!
        var key_info = forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(private_key));
        output_pem = [
            '-----BEGIN PRIVATE KEY-----',
            forge.util.encode64(forge.asn1.toDer(key_info).getBytes()),
            '-----END PRIVATE KEY-----'
        ].join('\r\n');
    }
    return {pem: output_pem, errors: null};
};
