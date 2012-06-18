var octokey = octokey || {};

octokey.privateKey = function (raw_private_key) {

    var _public = {},
        private_key = forge.pki.privateKeyFromPem(raw_private_key),
        service_name = "octokey-auth";

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
