var octokey = octokey || {};

/* Encapsulates one authentication request, i.e. the data related to a login attempt.
 * Must be initialized with an object containing three parameters:
 *   - challenge:   Unguessable opaque string set by the server, must be Base64
 *   - request_url: URL of the login endpoint for which the request is being generated
 *   - username:    Username or email address by which the server can identify the user
 */
octokey.authRequest = function (params) {
    var _public = {}, signed = null;

    /* Returns a binary string analogous to a pubkey SSH_MSG_USERAUTH_REQUEST, as
     * described in RFC4252. */
    function dataToBeSigned(public_key) {
        var buf = new forge.util.ByteBuffer();
        buf.putBinaryString(params.challenge);
        buf.putBinaryString(params.request_url);
        buf.putBinaryString(params.username);
        buf.putBinaryString('octokey-auth');       // service name
        buf.putBinaryString('publickey');          // authentication method
        buf.putBinaryString('ssh-rsa');            // signing algorithm name
        buf.putBinaryString(public_key.toBytes()); // public key corresponding to the signing key
        return buf.data;
    }

    /* Updates this auth request object to carry a signature by the given private key.
     * Returns true if successful, false on failure (e.g. private key is locked). */
    _public.sign = function (private_key) {
        var public_key = private_key.publicKey();
        if (!public_key) {
            return false;
        }

        var data = dataToBeSigned(public_key),
            signature = private_key.sign(data);

        if (!signature) {
            return false;
        }

        var buf = new forge.util.ByteBuffer(data);
        buf.putBinaryString(signature);
        signed = buf.data;
        return true;
    };

    _public.toBytes = function () {
        return signed;
    };

    /* Returns the signed, base64-encoded auth request in the form that we can send
     * to the server. Only valid after the auth request has been signed. */
    _public.toBase64 = function () {
        return signed ? forge.util.encode64(signed) : null;
    };

    return _public;
};
