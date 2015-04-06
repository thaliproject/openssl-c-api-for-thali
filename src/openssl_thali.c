
/*   openssl_thali.c */

/*
 *   Written by Srikanth Challa for the Thali project (thaliproject.org).
 */


#include "openssl_thali.h"


/*	Local functions. */
static void init_openssl(void);
static void cleanup_openssl(void);
static EVP_PKEY* create_rsa_key(int keysize);
static void handle_openssl_error(void);
static X509* create_x509_cert(EVP_PKEY *privkey);
static STACK_OF(X509)* create_ca_cert_stack(X509 *cert);
static void* free_openssl_resources(EVP_PKEY *key, X509 *cert, STACK_OF(X509) *certstack);

//TODO: Remove this main function
int main(int argc, char **argv)
{
     PKCS12 *pkcs12 = NULL;
     
     pkcs12 = create_PKCS12_stream(4096, "password");
     
     if(pkcs12 == NULL)
     {
          printf("ERROR>>>>>>>>>>>>>>>>>>>>>>>>>\n");
     }
     return 0;
}


/*
 * 	Pass the key-size and the password and this function returns
 * 	the PKCS12 structure as a stream.
 */
PKCS12* create_PKCS12_stream(int keysize, const char *password)
{
     EVP_PKEY *privkey = NULL;
     X509 *x509_cert = NULL;
     STACK_OF(X509) *cacertstack = NULL;
     PKCS12 *pkcs12bundle = NULL;
     
     if(!keysize || !password)
     {
          fprintf(stderr,"Invalid key-size and/or password.\n");
          return NULL;
     }
     
     init_openssl();
     
     privkey = create_rsa_key(keysize);
     if(privkey == NULL)
     {
          return (PKCS12*)free_openssl_resources(privkey, x509_cert, cacertstack);
     }
     fprintf(stdout,"successfully created rsa key.\n");
     
     x509_cert = create_x509_cert(privkey);
     if(x509_cert == NULL)
     {
          return (PKCS12*)free_openssl_resources(privkey, x509_cert, cacertstack);
     }
     fprintf(stdout,"successfully created x509 certificate.\n");
     
     cacertstack = create_ca_cert_stack(x509_cert);
     if(cacertstack == NULL)
     {
          return (PKCS12*)free_openssl_resources(privkey, x509_cert, cacertstack);
     }
     fprintf(stdout,"successfully created stack-of-x509.\n");
     
     if ((pkcs12bundle = PKCS12_new()) == NULL)
     {
          fprintf(stderr,"PKCS12_new failed.\n");
          return (PKCS12*)free_openssl_resources(privkey, x509_cert, cacertstack);
     }
	pkcs12bundle = PKCS12_create(
                         (char*)password,	// certbundle access password
                         "thali",	// friendly certname
                         privkey,	// the certificate private key
                         x509_cert,	// the main certificate
                         cacertstack,	// stack of CA cert chain
                         0,	// int nid_key (default 3DES)
                         0,	// int nid_cert (40bitRC2)
                         0,	// int iter (default 2048)
                         0,	// int mac_iter (default 1)
                         0	// int keytype (default no flag)
                         );
     if (pkcs12bundle == NULL)
     {
          fprintf(stderr,"PKCS12_create failed.\n");
          return (PKCS12*)free_openssl_resources(privkey, x509_cert, cacertstack);
     }
     fprintf(stdout,"successfully created pkcs12 bundle.\n");
     
     free_openssl_resources(privkey, x509_cert, cacertstack);
     
     return pkcs12bundle; //TODO: Make this a stream (char *)
}

void* free_openssl_resources(EVP_PKEY *key, X509 *cert, STACK_OF(X509) *certstack)
{
     if(certstack != NULL)
     {
          sk_X509_free(certstack);
     }
     if(cert != NULL)
     {
          X509_free(cert);
     }
     if(key != NULL)
     {
          EVP_PKEY_free(key);
     }
     cleanup_openssl();
     return NULL;
}

STACK_OF(X509)* create_ca_cert_stack(X509 *cert)
{
     STACK_OF(X509) *certstack;
     if ((certstack = sk_X509_new_null()) == NULL)
     {
          fprintf(stderr,"sk_X509_new_null failed.\n");
          return NULL;
     }
     sk_X509_push(certstack, cert);
     return certstack;
}

X509* create_x509_cert(EVP_PKEY *privkey)
{
     X509 *x509;
     x509 = X509_new();
     
     ASN1_INTEGER_set(X509_get_serialNumber(x509), 0);
     
     X509_gmtime_adj(X509_get_notBefore(x509), 0); //current time
     X509_gmtime_adj(X509_get_notAfter(x509), 31536000L); //valid for 365 days
     
     X509_set_pubkey(x509, privkey);
     
     X509_NAME *name;
     name = X509_get_subject_name(x509); //set the name of the issuer to the name of the subject
     
     X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC,
                                   (unsigned char *)"US", -1, -1, 0); //country
     X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC,
                                   (unsigned char *)"Microsoft", -1, -1, 0); //organization
     X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   (unsigned char *)"Thali", -1, -1, 0); //common name
     
     X509_set_issuer_name(x509, name); //set the issuer name
     
     int ret = X509_sign(x509, privkey, EVP_sha1()); //using the SHA-1 hashing algorithm to sign the key (MD5 is another option)
     if(!ret)
     {
          fprintf(stderr,"X509_sign failed.\n");
          return NULL;
     }
     return x509;
}

EVP_PKEY* create_rsa_key(int keysize)
{
     RSA *pRSA = NULL;
     EVP_PKEY *pKey = NULL;
     BIGNUM *e = NULL;
     int ret;
     
     pRSA = RSA_new();
     pKey = EVP_PKEY_new();
     e = BN_new();
     BN_set_word(e, 65537);
     
     ret = RSA_generate_key_ex(pRSA, keysize, e, NULL);
     
     if(ret && pKey && EVP_PKEY_assign_RSA(pKey, pRSA))
     {
          /* pKey owns pRSA from now */
          if(RSA_check_key(pRSA) <= 0)
          {
               fprintf(stderr,"RSA_check_key failed.\n");
               handle_openssl_error();
               EVP_PKEY_free(pKey);
               pKey = NULL;
          }
     }
     else
     {
          handle_openssl_error();
          if(pRSA)
          {
               RSA_free(pRSA);
               pRSA = NULL;
          }
          if(pKey)
          {
               EVP_PKEY_free(pKey);
               pKey = NULL;
          }
     }
     BN_free(e);
     return pKey;
}

void init_openssl(void)
{
     if(SSL_library_init())
     {
          SSL_load_error_strings();
          OpenSSL_add_all_algorithms();
          RAND_load_file("/dev/urandom", 1024);
     }
     else
     {
          exit(EXIT_FAILURE);
     }
}

void cleanup_openssl(void)
{
     CRYPTO_cleanup_all_ex_data();
     ERR_free_strings();
     ERR_remove_thread_state(0);
     EVP_cleanup();
}

void handle_openssl_error(void)
{
     ERR_print_errors_fp(stderr);
}

