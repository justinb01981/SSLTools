#ifndef __SSLTOOL_CONFIG_H__
#define __SSLTOOL_CONFIG_H__

#include <openssl/rsa.h>       /* SSLeay stuff */
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* hack to workaround OPENSSL wierdness */
#if OPENSSL_VERSION_NUMBER == 0x0090709fL
#define ERR_print_errors_fp(x)
#endif

#endif
