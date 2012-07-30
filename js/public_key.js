var octokey = octokey || {};

/* Encapsulates a SSH RSA public key, given two bignums:
 *  - e, the RSA public exponent
 *  - n, the RSA modulus */
octokey.publicKey = function (e, n) {
    var _public = {};

    /* Returns the public key as a binary string in RFC4253 format. */
    _public.toBytes = function () {
        var buf = new forge.util.ByteBuffer();
        buf.putBinaryString('ssh-rsa');
        buf.putBignum(e);
        buf.putBignum(n);
        return buf.data;
    };

    /* Returns the public key as a string in the format that you typically find
     * in ~/.ssh/authorized_keys files. */
    _public.toBase64 = function () {
        return 'ssh-rsa ' + forge.util.encode64(_public.toBytes());
    };

    return _public;
};
