/* build with: gcc -lssl -lcrypto -o minimal minimal.c */

#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

#define PRIVATE_KEY_FILENAME "/Users/martin/.ssh/test_rsa_key"
#define USERNAME "martin"
#define REQUEST_URL "https://www.example.com/login"
#define SESSIONID "\x29\x69\xb9\x3c\xc4\x02\xdd\x46\x12\x15\x8f\xf1\x80\xb8\xa6\x1e\xf2\xe1\x2d\xcb\x88\x77\x04\x59\xa0\x39\xb8\x51\xf1\x00\x0c\xed"
#define SESSIONID_LEN 32

#define MAX_KEY_FILE_SIZE 10240
#define MAX_KEY_BLOB_SIZE 10240
#define MAX_BIGNUM_SIZE 10240
#define MAX_AUTHDATA_SIZE 65536
#define MAX_SIGNATURE_SIZE 1024
#define INTBLOB_LEN 20
#define SIGBLOB_LEN (2*INTBLOB_LEN)


/* 32 bits, network byte order */
void put_u32(unsigned char *buf, unsigned int value) {
    buf[0] = (unsigned char)(value >> 24) & 0xff;
    buf[1] = (unsigned char)(value >> 16) & 0xff;
    buf[2] = (unsigned char)(value >> 8) & 0xff;
    buf[3] = (unsigned char) value & 0xff;
}

/* The "string" type of RFC4251 */
size_t append_string(unsigned char *dst, const unsigned char *src, size_t maxlen) {
    if (maxlen < 4) return 4;
    size_t len = strlen(src);
    put_u32(dst, len);
    return strlcpy(dst + 4, src, maxlen - 4) + 4;
}

size_t append_bytes(unsigned char *dst, const unsigned char *src, size_t len) {
    put_u32(dst, len);
    memcpy(dst + 4, src, len);
    return len + 4;
}

/* Encodes an OpenSSL BIGNUM as a RFC4251 string */
size_t append_bignum(unsigned char *dst, const BIGNUM *value, size_t maxlen) {
    if (maxlen < 4) return 4;
    if (BN_is_zero(value)) {
        put_u32(dst, 0);
        return 4;
    }
    if (value->neg) {
        fprintf(stderr, "negative numbers not supported\n");
        exit(1);
    }

    unsigned char bytes[MAX_BIGNUM_SIZE];
    unsigned int length = BN_num_bytes(value) + 1;
    if (length > maxlen - 4) length = maxlen - 4;

    bytes[0] = 0;
    BN_bn2bin(value, bytes + 1);

    // The MSB of the first byte is interpreted as a sign bit (RFC4251 section 5, "mpint").
    // Our number is always positive (check above), therefore if that bit is set, we
    // need to insert a zero byte to make sure the number is interpreted correctly.
    unsigned int offset = (bytes[1] & 0x80) ? 0 : 1;
    return append_bytes(dst, bytes + offset, length - offset);
}


/* RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature) with SHA1, based on OpenSSH.
 * Note from RFC3447:
 * Although no attacks are known against RSASSA-PKCS1-v1_5, in the interest of
 * increased robustness, RSASSA-PSS is recommended for eventual adoption in new
 * applications.
 */
void ssh_rsa_sign(const EVP_PKEY *key, unsigned char *sig_r, unsigned int *len_r, const unsigned char *data, unsigned int datalen) {
    EVP_MD_CTX md;
    unsigned char digest[EVP_MAX_MD_SIZE], sig[MAX_SIGNATURE_SIZE];
    unsigned int dlen, len;

    EVP_DigestInit(&md, EVP_sha1());
    EVP_DigestUpdate(&md, data, datalen);
    EVP_DigestFinal(&md, digest, &dlen);

    RSA *rsa = EVP_PKEY_get1_RSA(key);
    unsigned int slen = RSA_size(rsa);

    if (RSA_sign(NID_sha1, digest, dlen, sig, &len, rsa) != 1) {
        fprintf(stderr, "RSA_sign failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        exit(1);
    }
    if (len < slen) {
        unsigned int diff = slen - len;
        memmove(sig + diff, sig, len);
        memset(sig, 0, diff);
    } else if (len > slen) {
        fprintf(stderr, "ssh_rsa_sign: slen %u slen2 %u\n", slen, len);
        exit(1);
    }

    *len_r = append_string(sig_r, "ssh-rsa", 12);
    *len_r += append_bytes(sig_r + (*len_r), sig, slen);
}


int main(int argc, char **argv) {
    FILE *keyfile = fopen(PRIVATE_KEY_FILENAME, "r");
    if (!keyfile) {
        fprintf(stderr, "couldn't open private key file\n");
        return 1;
    }

    EVP_PKEY *key = PEM_read_PrivateKey(keyfile, NULL, NULL, NULL);
    fclose(keyfile);
    if (!key) {
        fprintf(stderr, "couldn't load private key (note: keys with passphrase are not yet supported)\n");
        return 1;
    }

    unsigned char key_blob[MAX_KEY_BLOB_SIZE];
    int blob_len = 0;

    char *algorithm_name;
    if (key->type == EVP_PKEY_RSA) {
        RSA *rsa = EVP_PKEY_get1_RSA(key);
        algorithm_name = "ssh-rsa";
        blob_len += append_string(key_blob + blob_len, algorithm_name, MAX_KEY_BLOB_SIZE - blob_len);
        if (blob_len >= MAX_KEY_BLOB_SIZE) return 1;
        blob_len += append_bignum(key_blob + blob_len, rsa->e, MAX_KEY_BLOB_SIZE - blob_len);
        if (blob_len >= MAX_KEY_BLOB_SIZE) return 1;
        blob_len += append_bignum(key_blob + blob_len, rsa->n, MAX_KEY_BLOB_SIZE - blob_len);
        if (blob_len >= MAX_KEY_BLOB_SIZE) return 1;
    } else {
        fprintf(stderr, "Sorry, only RSA keys are supported.\n");
        return 1;
    }

    unsigned char authdata[MAX_AUTHDATA_SIZE];
    int auth_len = 0;

    auth_len += append_bytes(authdata + auth_len, SESSIONID, SESSIONID_LEN);
    if (auth_len >= MAX_AUTHDATA_SIZE) return 1;
    auth_len += append_string(authdata + auth_len, REQUEST_URL, MAX_AUTHDATA_SIZE - auth_len);
    if (auth_len >= MAX_AUTHDATA_SIZE) return 1;
    auth_len += append_string(authdata + auth_len, USERNAME, MAX_AUTHDATA_SIZE - auth_len);
    if (auth_len >= MAX_AUTHDATA_SIZE) return 1;
    auth_len += append_string(authdata + auth_len, "ssh-connection", MAX_AUTHDATA_SIZE - auth_len);
    if (auth_len >= MAX_AUTHDATA_SIZE) return 1;
    auth_len += append_string(authdata + auth_len, "publickey", MAX_AUTHDATA_SIZE - auth_len);
    if (auth_len >= MAX_AUTHDATA_SIZE) return 1;
    auth_len += append_string(authdata + auth_len, algorithm_name, MAX_AUTHDATA_SIZE - auth_len);
    if (auth_len >= MAX_AUTHDATA_SIZE) return 1;
    auth_len += append_bytes(authdata + auth_len, key_blob, blob_len);
    if (auth_len >= MAX_AUTHDATA_SIZE) return 1;

    unsigned char signature[MAX_SIGNATURE_SIZE];
    unsigned int sig_len;

    ssh_rsa_sign(key, signature, &sig_len, authdata, auth_len);
    auth_len += append_bytes(authdata + auth_len, signature, sig_len);
    if (auth_len >= MAX_AUTHDATA_SIZE) return 1;

    fwrite(authdata, 1, auth_len, stdout);

    return 0;
}
