/* Independent OpenSSL verifier. Input: public key[1312], signature[2420],
 * message to EOF. */
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <stdio.h>
int main(void) {
  unsigned char pk[1312], sig[2420], msg[4096];
  if (fread(pk, 1, sizeof pk, stdin) != sizeof pk ||
      fread(sig, 1, sizeof sig, stdin) != sizeof sig)
    return 2;
  size_t n = fread(msg, 1, sizeof msg, stdin);
  if (!feof(stdin))
    return 2;
  EVP_PKEY *key =
      EVP_PKEY_new_raw_public_key_ex(NULL, "ML-DSA-44", NULL, pk, sizeof pk);
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  char domain[] = "TOS-CONSENSUS-SIMPLEX-v1";
  OSSL_PARAM params[] = {
      OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, domain,
                              sizeof(domain) - 1),
      OSSL_PARAM_END};
  int result =
      key && ctx &&
      EVP_DigestVerifyInit_ex(ctx, NULL, NULL, NULL, NULL, key, params) == 1 &&
      EVP_DigestVerify(ctx, sig, sizeof sig, msg, n) == 1;
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(key);
  return result ? 0 : 1;
}
