var octokey = octokey || {};

octokey.privateKey = function (raw_private_key) {

    var _public = {},
        private_key = null,
        decrypt_key = null, // function: passphrase -> private key
        passphrase_timeout = 5 * 60 * 1000, // 5 minutes in milliseconds
        passphrase_timer = null,
        service_name = "octokey-auth";

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
                // TODO more ciphers
                'AES-128-CBC': {algorithm: forge.aes, key_len: 16}
            }[cipher_info[1]];

            if (!cipher) {
                throw 'unsupported private key encryption cipher: ' + cipher_info[1];
            }

            decrypt_key = function (passphrase) {
                // The following algorithm for deriving the key is hard-coded in OpenSSL
                var md = forge.md.md5.create();
                md.update(passphrase, 'utf-8');
                md.update(init_vector.substr(0, 8)); // the first PKCS5_SALT_LEN (8) bytes of IV are used as salt
                var key = md.digest().getBytes(cipher.key_len);

                var decrypt = cipher.algorithm.startDecrypting(key, init_vector);
                decrypt.update(data);
                decrypt.finish();
                return forge.pki.privateKeyFromAsn1(forge.asn1.fromDer(decrypt.output));
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


    // Appends an RFC4251 binary "string" type to a byte buffer.
    function appendString(buf, str) {
        buf.putInt32(str.length);
        buf.putBytes(str);
    }

    // Appends a RFC4251 "mpint" type to a buffer. That's a multi-precision int,
    // not a multi-pint, I'm afraid.
    function appendBignum(buf, value) {
        var hex = value.toString(16);
        // The MSB of the first byte is interpreted as a sign bit. Our numbers are
        // always positive, therefore if that bit is set, we need to insert a zero
        // byte to make sure the number is interpreted correctly.
        if (hex[0] >= '8') {
            hex = '00' + hex;
        }
        appendString(buf, forge.util.hexToBytes(hex));
    }

    // Extracts the public key, in RFC4253 format, from the private key object.
    function publicKey() {
        var buf = new forge.util.ByteBuffer();
        appendString(buf, 'ssh-rsa');
        appendBignum(buf, private_key.e);
        appendBignum(buf, private_key.n);
        return buf.data;
    }

    // Byte buffer to be signed for a pubkey SSH_MSG_USERAUTH_REQUEST, as
    // described in RFC4252.
    function userAuthRequest(params) {
        var buf = new forge.util.ByteBuffer();
        appendString(buf, params.challenge);  // unguessable opaque string set by the server
        appendString(buf, params.request_url);// URL of the login endpoint for which the request is intended
        appendString(buf, params.username);   // user name for login
        appendString(buf, service_name);      // service name
        appendString(buf, "publickey");       // authentication method
        appendString(buf, "ssh-rsa");         // signing algorithm name
        appendString(buf, _public.publicKey());        // public key corresponding to the signing key
        return buf.data;
    }

    // RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature) with SHA1, as defined in RFC3447,
    // and used in SSH as described in RFC4253.
    function signAuthRequest(request) {
        var digest = forge.md.sha1.create(),
            buf = new forge.util.ByteBuffer();

        digest.update(request);
        appendString(buf, 'ssh-rsa');
        appendString(buf, private_key.sign(digest));
        return buf.data;
    }

    // Pretty-printed hex dump for debugging
    function prettyHex(buffer) {
        var offset = 0;
        return $.map(buffer.toHex().split(/([0-9a-f]{32})/), function (line) {
            if (line) {
                line = line.replace(/([0-9a-f]{4})/g, '$1 ');
                var off = offset.toString(16) + ': ';
                while (off.length < 9) {
                    off = '0' + off;
                }
                offset += 16;
                return off + line.trimRight();
            }
        }).join("\n");
    }

    _public.publicKey = function () {
        var buf = new forge.util.ByteBuffer();
        appendString(buf, 'ssh-rsa');
        appendBignum(buf, private_key.e);
        appendBignum(buf, private_key.n);
        return buf.data;
    };

    _public.publicKey64 = function () {
        return forge.util.encode64(_public.publicKey());
    };

    _public.authRequest = function (params) {
        var request = userAuthRequest(params),
            signature = signAuthRequest(request),
            auth_request = new forge.util.ByteBuffer(request);

        appendString(auth_request, signature);
        return auth_request;
    };

    _public.authRequest64 = function (params) {
        return forge.util.encode64(_public.authRequest(params).data);
    };

    _public.authRequestPretty = function (params) {
        return prettyHex(_public.authRequest(params));
    };

    return _public;
};
