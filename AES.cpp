#include "stdafx.h"
#include "AES.h"
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#define EVP_MAX_KEY_LENGHT 64

AES::AES()
{
}


AES::~AES()
{
}

string AES::encrypt(string input, string key)
{
    int rv;
    int outlen1, outlen2;
    EVP_CIPHER_CTX *ctx = 0;
    unsigned char* out = 0;
    unsigned char ivec[16] = { 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12};

    if (input.empty()) {
        throw invalid_argument("input parameter empty");
    }

    if (key.empty()) {
        throw invalid_argument("key parameter empty");
    }

    if (key.length() > EVP_MAX_KEY_LENGHT) {
        throw invalid_argument("key length greater than 64");
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw exception("EVP_CIPHER_CTX_new alloc fail");
    }

    rv = EVP_CipherInit_ex(ctx, EVP_aes_256_ecb(), NULL, (const unsigned char*)key.c_str(), ivec, AES_ENCRYPT);
    if (1 != rv) {
        printf("EVP_CipherInit_ex error:%d\r\n", rv);
        throw exception("EVP_CipherInit_ex error", rv);
    }

    size_t maxlen = input.length() + AES_BLOCK_SIZE;
    out = (unsigned char*)malloc(maxlen);
    if (!out) {
        throw exception("out alloc fail");
    }

    rv = EVP_CipherUpdate(ctx, out, &outlen1, (const unsigned char*)input.c_str(), input.length());
    if (1 != rv) {
        printf("EVP_CipherUpdate error:%d\r\n", rv);
        throw exception("EVP_CipherUpdate error", rv);
    }

    rv = EVP_CipherFinal(ctx, out + outlen1, &outlen2);
    if (1 != rv) {
        printf("EVP_CipherFinal error:%d\r\n", rv);
        throw exception("EVP_CipherFinal error", rv);
    }

    EVP_CIPHER_CTX_free(ctx);

    string result((const char*)out, outlen1 + outlen2);
    free(out);
    return result;
}

string AES::decrypt(string input, string key)
{
    int rv;
    int outlen1, outlen2;
    EVP_CIPHER_CTX *ctx = 0;
    unsigned char* out = 0;
    unsigned char ivec[16] = { 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12 };

    if (input.empty()) {
        throw invalid_argument("input parameter empty");
    }

    if (key.empty()) {
        throw invalid_argument("key parameter empty");
    }

    if (key.length() > EVP_MAX_KEY_LENGHT) {
        throw invalid_argument("key length greater than 64");
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw exception("EVP_CIPHER_CTX_new alloc fail");
    }

    rv = EVP_CipherInit_ex(ctx, EVP_aes_256_ecb(), NULL, (const unsigned char*)key.c_str(), ivec, AES_DECRYPT);
    if (1 != rv) {
        printf("EVP_CipherInit_ex error:%d\r\n", rv);
        throw exception("EVP_CipherInit_ex error", rv);
    }

    size_t maxlen = input.length();
    out = (unsigned char*)malloc(maxlen);
    if (!out) {
        throw exception("out alloc fail");
    }

    rv = EVP_CipherUpdate(ctx, out, &outlen1, (const unsigned char*)input.c_str(), input.length());
    if (1 != rv) {
        printf("EVP_CipherUpdate error:%d\r\n", rv);
        throw exception("EVP_CipherUpdate error", rv);
    }

    rv = EVP_CipherFinal(ctx, out + outlen1, &outlen2);
    if (1 != rv) {
        printf("EVP_CipherFinal error:%d\r\n", rv);
        throw exception("EVP_CipherFinal error", rv);
    }

    EVP_CIPHER_CTX_free(ctx);

    string result((const char*)out, outlen1 + outlen2);
    free(out);

    return result;
}
