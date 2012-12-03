/* build with: gcc -lssl -lcrypto -o minimal minimal.c */

#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

#define PRIVATE_KEY_FILENAME "/tmp/octokey.private"
#define USERNAME "alfred@test.linkedin.com"
#define REQUEST_URL "https://eat1-app45.corp.linkedin.com:8443/uas/login-submit"
#define SESSIONID "\x29\x69\xb9\x3c\xc4\x02\xdd\x46\x12\x15\x8f\xf1\x80\xb8\xa6\x1e\xf2\xe1\x2d\xcb\x88\x77\x04\x59\xa0\x39\xb8\x51\xf1\x00\x0c\xed"
#define SESSIONID_LEN 32
#define SERVICE_NAME "octokey-auth"

#define MAX_KEY_FILE_SIZE 10240
#define MAX_KEY_BLOB_SIZE 10240
#define MAX_BIGNUM_SIZE 10240
#define MAX_AUTHDATA_SIZE 65536
#define MAX_SIGNATURE_SIZE 1024
#define INTBLOB_LEN 20
#define SIGBLOB_LEN (2*INTBLOB_LEN)

size_t strlcpy(unsigned char *dst, const unsigned char *src, size_t maxlen) {
    size_t len = strlen(src);
    size_t to_copy = len;

    if (len >= maxlen - 1) {
        to_copy = maxlen - 1;
    }

    strncpy(dst, src, to_copy);
    dst[to_copy + 1] = '\0';

    return len;
}

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

int rsa_private_encrypt(int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding) {


    BIGNUM *f, *ret, *res, *ret1, *ret2;
    int i,j,k,num=0,r= -1;
    unsigned char *buf=NULL;
    BN_CTX *ctx=NULL;

    if ((ctx=BN_CTX_new()) == NULL) goto err;
    BN_CTX_start(ctx);
    f   = BN_CTX_get(ctx);
    ret = BN_CTX_get(ctx);
    ret1 = BN_CTX_get(ctx);
    ret2 = BN_CTX_get(ctx);
    num = BN_num_bytes(rsa->n);
    buf = OPENSSL_malloc(num);

    if (!f || !ret || !buf) {
        printf("ERR_R_MALLOC_FAILURE");
        exit(1);
    }

    i = RSA_padding_add_PKCS1_type_1(buf,num,from,flen);
    if (i <= 0) goto err;

    if (BN_bin2bn(buf,num,f) == NULL) goto err;

    if (BN_ucmp(f, rsa->n) >= 0) {
        /* usually the padding functions would catch this */
        printf("RSA_R_DATA_TOO_LARGE_FOR_MODULUS");
        exit(1);
    }

    BIGNUM local_d1, local_d2;
    BIGNUM *d1 = NULL, *d2 = NULL;


    BN_init(&local_d1);
    BN_init(&local_d2);
    d1 = &local_d1;
    d2 = &local_d2;

    BN_rand_range(d1, rsa->d);
    BN_sub(d2, rsa->d, d1);


    // TODO: is this NULL a security/performance problem?
    // need to figure out what happens if rsa->flags & RSA_FLAG_CACHE_PUBLIC
    // w.r.t. rsa->_method_mod_n
    // TODO: re-instate CONST TIME flags and/or blinding.
    if (!BN_mod_exp_mont(ret1, f, d1, rsa->n, ctx, NULL)) goto err;

    if (!BN_mod_exp_mont(ret2, f, d2, rsa->n, ctx, NULL)) goto err;

    if (!BN_mod_mul(ret, ret1, ret2, rsa->n, ctx)) goto err;

    res = ret;

    /* put in leading 0 bytes if the number is less than the
     * length of the modulus */
    j=BN_num_bytes(res);
    i=BN_bn2bin(res,&(to[num-j]));
    for (k=0; k<(num-i); k++)
            to[k]=0;

    r=num;
err:
    if (ctx != NULL) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if (buf != NULL) {
        OPENSSL_cleanse(buf,num);
        OPENSSL_free(buf);
    }
    return(r);
}

// Inlined from RSA_sign
int rsa_sign(int type, const unsigned char *m, unsigned int m_len,
             unsigned char *sigret, unsigned int *siglen, RSA *rsa) {

    X509_SIG sig;
    ASN1_TYPE parameter;
    int i,j,ret=1;
    unsigned char *p, *tmps = NULL;
    const unsigned char *s = NULL;
    X509_ALGOR algor;
    ASN1_OCTET_STRING digest;

    sig.algor= &algor;
    sig.algor->algorithm=OBJ_nid2obj(type);
    if (sig.algor->algorithm == NULL) {
        printf("RSA_R_UNKNOWN_ALGORITHM_TYPE\n");
        exit(1);
    }
    if (sig.algor->algorithm->length == 0) {
        printf("RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD\n");
        exit(1);
    }
    parameter.type=V_ASN1_NULL;
    parameter.value.ptr=NULL;
    sig.algor->parameter= &parameter;

    sig.digest= &digest;
    sig.digest->data=(unsigned char *)m; /* TMP UGLY CAST */
    sig.digest->length=m_len;

    i=i2d_X509_SIG(&sig,NULL);
    j=RSA_size(rsa);
    if (i > (j-RSA_PKCS1_PADDING_SIZE)) {
        printf("RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY");
        exit(1);
    }

    tmps=(unsigned char *)OPENSSL_malloc((unsigned int)j+1);
    if (tmps == NULL) {
        printf("ERR_R_MALLOC_FAILURE");
        return(0);
    }
    p=tmps;
    i2d_X509_SIG(&sig,&p);
    s=tmps;

    i=rsa_private_encrypt(i,s,sigret,rsa,RSA_PKCS1_PADDING);
    if (i <= 0)
        ret=0;
    else
        *siglen=i;

    OPENSSL_cleanse(tmps,(unsigned int)j+1);
    OPENSSL_free(tmps);
    return(ret);
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

    RSA *rsa = EVP_PKEY_get1_RSA((EVP_PKEY *)key);
    unsigned int slen = RSA_size(rsa);

    if (rsa_sign(NID_sha1, digest, dlen, sig, &len, rsa) != 1) {
        char errbuf[8096];
        ERR_error_string_n(ERR_get_error(), errbuf, 8096);
        fprintf(stderr, "RSA_sign failed: %s\n", errbuf);
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
    auth_len += append_string(authdata + auth_len, SERVICE_NAME, MAX_AUTHDATA_SIZE - auth_len);
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
