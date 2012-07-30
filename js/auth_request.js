var octokey = octokey || {};

/* Encapsulates one authentication request, i.e. the data related to a login attempt.
 * Must be initialized with an object containing three parameters:
 *   - challenge:   Unguessable opaque string set by the server, must be Base64
 *   - request_url: URL of the login endpoint for which the request is being generated
 *   - username:    Username or email address by which the server can identify the user
 */
octokey.authRequest = function (params) {
    var _public = {}, signed = null, errors = [], challenge, request_url, username;

    // Boring parameter checking, and conversion into binary strings

    if (typeof(params.challenge) === 'string') {
        // We don't assume any particular challenge format, but fewer than 64 bits is
        // unlikely to be secure enough
        if (params.challenge.length >= 11) {
            if (!params.challenge.match(/[^A-Za-z0-9\+\/\=]/)) {
                challenge = forge.util.decode64(params.challenge);
            } else {
                errors.push('challenge contains invalid characters, must be base64');
            }
        } else {
            errors.push('challenge is too short');
        }
    } else {
        errors.push('challenge is not a string');
    }

    if (typeof(params.request_url) === 'string') {
        // Not enforcing https here, for convenience of development environments.
        // But please note that using Octokey over plain http is not safe.
        if (params.request_url.match(/^https?:\/\/.+/)) {
            request_url = forge.util.encodeUtf8(params.request_url);
        } else {
            errors.push('request_url is not valid');
        }
    } else {
        errors.push('request_url is not a string');
    }

    if (typeof(params.username) === 'string') {
        if (params.username.length >= 1) {
            username = forge.util.encodeUtf8(params.username);
        } else {
            errors.push('username is too short');
        }
    } else {
        errors.push('username is not a string');
    }


    /* Returns a binary string analogous to a pubkey SSH_MSG_USERAUTH_REQUEST, as
     * described in RFC4252. */
    function dataToBeSigned(public_key) {
        var buf = new forge.util.ByteBuffer();
        buf.putBinaryString(challenge);
        buf.putBinaryString(request_url);
        buf.putBinaryString(username);
        buf.putBinaryString('octokey-auth');       // service name
        buf.putBinaryString('publickey');          // authentication method
        buf.putBinaryString('ssh-rsa');            // signing algorithm name
        buf.putBinaryString(public_key.toBytes()); // public key corresponding to the signing key
        return buf.data;
    }

    /* Updates this auth request object to carry a signature by the given private key.
     * Returns true if successful, false on failure (e.g. private key is locked). */
    _public.sign = function (private_key) {
        if (errors.length > 0) {
            return false;
        }

        var public_key = private_key.publicKey();
        if (!public_key) {
            errors.push('private key is locked');
            return false;
        }

        var data = dataToBeSigned(public_key),
            signature = private_key.sign(data);

        if (!signature) {
            errors.push('private key is unable to sign the auth request');
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

    _public.isValid = function () {
        return errors.length == 0;
    };

    _public.errors = function () {
        return errors;
    };

    return _public;
};
