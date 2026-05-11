/* Legacy OpenSSL crypto sample for the binary/source scanner tests. */
#include <openssl/rsa.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <openssl/dh.h>

int make_rsa(void) {
    RSA *r = RSA_generate_key_ex(NULL, 2048, NULL, NULL);
    return r ? 0 : -1;
}

int make_ec(void) {
    EC_KEY *k = EC_KEY_new_by_curve_name(415);
    return k ? 0 : -1;
}

int compute_dh(DH *dh, unsigned char *out, const unsigned char *in) {
    return DH_compute_key(out, NULL, dh);
}

int do_ecdh(EC_KEY *priv, EC_POINT *peer, unsigned char *out) {
    return ECDH_compute_key(out, 32, peer, priv, NULL);
}
