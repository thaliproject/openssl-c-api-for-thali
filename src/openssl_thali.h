
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>


PKCS12* create_PKCS12_stream(int keysize, const char *password);

