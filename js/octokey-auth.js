/*jslint onevar: false*/
var octokey = octokey || {};
// params is an object containing {
//
// private_key_pem:  The private key in PEM format,
// username:  The username to authenticate as,
// challenge:  The challenge from the server.
//
// }
octokey.auth = function (params) {

    if (!params.private_key_pem) {
        throw "no private_key_pem given";
    }

    var private_key = forge.pki.privateKeyFromPem(params.private_key_pem),
        service_name = params.service_name || 'octokey-auth',
        public_key,
        output;

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
    function userAuthRequest() {
        var buf = new forge.util.ByteBuffer();
        appendString(buf, params.challenge);  // unguessable opaque string set by the server
        buf.putByte(50);                      // SSH_MSG_USERAUTH_REQUEST
        appendString(buf, params.username);   // user name for login
        appendString(buf, service_name);      // service name
        appendString(buf, "publickey");       // authentication method
        buf.putByte(1);                       // is a signature included? yes!
        appendString(buf, "ssh-rsa");         // signing algorithm name
        appendString(buf, public_key);        // public key corresponding to the signing key
        return buf.data;
    }

    // RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature) with SHA1, as defined in RFC3447,
    // and used in SSH as described in RFC4253.
    function signAuthRequest(request) {
        var digest = forge.md.sha1.create();
        digest.update(request);
        var buf = new forge.util.ByteBuffer();
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

    // In any case, return the public key that we extracted out of private_key_pem.
    public_key = publicKey();
    output = {
        public_key: public_key,
        public_key_base64: forge.util.encode64(public_key) // this is what you find in ~/.ssh/id_rsa.pub
    };

    // If a challenge and username were given, generate a signed auth request using those details.
    if (params.challenge && params.username) {
        var request = userAuthRequest();
        var signature = signAuthRequest(request);
        var auth_request = new forge.util.ByteBuffer(request);
        appendString(auth_request, signature);

        output.auth_request = auth_request;
        output.auth_request_base64 = forge.util.encode64(auth_request.data);
        output.auth_request_pretty = prettyHex(auth_request);
    }

    return output;
};
