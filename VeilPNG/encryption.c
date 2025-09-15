// encryption.c

#include "encryption.h"
#include "../compat/compat.h"

#include <string.h>
#include <stdlib.h>
#include <tchar.h>
#include <stdio.h>

#ifdef _WIN32
// Include Windows headers without conflicting macros
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#endif

#define KEY_SIZE 32  // 256-bit key for AES-256
#define IV_SIZE 12   // 96-bit nonce for AES GCM
#define SALT_SIZE 16
#define TAG_SIZE 16  // 128-bit authentication tag

// Static buffer to hold error messages
static TCHAR encryption_error_message[512];

const TCHAR* get_encryption_error_message() {
    return encryption_error_message;
}

// Function prototypes
int derive_key_iv(const TCHAR* password, unsigned char* salt, unsigned char* key, unsigned char* iv);
#ifdef _WIN32
int pbkdf2_hmac_sha256(const unsigned char* password, size_t password_len,
    const unsigned char* salt, size_t salt_len,
    unsigned int iterations, unsigned char* output, size_t output_len);
#endif

// Function to encrypt data
int encrypt_data(unsigned char* plaintext, size_t plaintext_len, const TCHAR* password,
    unsigned char** ciphertext, size_t* ciphertext_len) {
#ifdef _WIN32
    NTSTATUS status;
    int ret = -1;

    unsigned char salt[SALT_SIZE];
    if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, salt, SALT_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("Random number generation failed."));
        return -1;
    }

    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];
    if (derive_key_iv(password, salt, key, iv) != 0) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("Key derivation failed."));
        return -1;
    }

    BCRYPT_ALG_HANDLE hAlg = NULL;
    if (!BCRYPT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("Failed to open AES algorithm provider."));
        return -1;
    }

    if (!BCRYPT_SUCCESS(status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0))) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("Failed to set chaining mode to GCM."));
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD keyObjectSize = 0;
    DWORD result = 0;
    if (!BCRYPT_SUCCESS(status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjectSize, sizeof(DWORD), &result, 0))) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("Failed to get key object size."));
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    PUCHAR keyObject = (PUCHAR)malloc(keyObjectSize);
    if (keyObject == NULL) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("Memory allocation failed."));
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    if (!BCRYPT_SUCCESS(status = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObject, keyObjectSize, key, KEY_SIZE, 0))) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("Failed to generate symmetric key."));
        free(keyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = iv;
    authInfo.cbNonce = IV_SIZE;
    authInfo.pbTag = (PUCHAR)malloc(TAG_SIZE);
    if (authInfo.pbTag == NULL) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("Memory allocation failed."));
        BCryptDestroyKey(hKey);
        free(keyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }
    authInfo.cbTag = TAG_SIZE;
    authInfo.pbAuthData = NULL;
    authInfo.cbAuthData = 0;

    *ciphertext_len = plaintext_len;
    *ciphertext = (unsigned char*)malloc(*ciphertext_len + SALT_SIZE + IV_SIZE + TAG_SIZE);
    if (*ciphertext == NULL) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("Memory allocation failed."));
        free(authInfo.pbTag);
        BCryptDestroyKey(hKey);
        free(keyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    ULONG cbResult = 0;
    if (!BCRYPT_SUCCESS(status = BCryptEncrypt(hKey, plaintext, (ULONG)plaintext_len, &authInfo, NULL, 0, *ciphertext + SALT_SIZE + IV_SIZE + TAG_SIZE, (ULONG)*ciphertext_len, &cbResult, 0))) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("Encryption failed."));
        free(*ciphertext);
        *ciphertext = NULL;
        free(authInfo.pbTag);
        BCryptDestroyKey(hKey);
        free(keyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }
    *ciphertext_len = cbResult + SALT_SIZE + IV_SIZE + TAG_SIZE;

    memcpy(*ciphertext, salt, SALT_SIZE);
    memcpy(*ciphertext + SALT_SIZE, iv, IV_SIZE);
    memcpy(*ciphertext + SALT_SIZE + IV_SIZE, authInfo.pbTag, TAG_SIZE);

    free(authInfo.pbTag);
    BCryptDestroyKey(hKey);
    free(keyObject);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    SecureZeroMemory(key, KEY_SIZE);

    ret = 0;
    return ret;
#else
    int ret = -1;
    unsigned char salt[SALT_SIZE];
    if (RAND_bytes(salt, SALT_SIZE) != 1) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("Random number generation failed."));
        return -1;
    }

    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];
    if (derive_key_iv(password, salt, key, iv) != 0) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("Key derivation failed."));
        return -1;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("Cipher context allocation failed."));
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("EncryptInit failed."));
        return -1;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("Set IV length failed."));
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("EncryptInit key/iv failed."));
        return -1;
    }

    int outlen = (int)plaintext_len + 16; // approx
    unsigned char* outbuf = (unsigned char*)malloc(outlen);
    if (!outbuf) {
        EVP_CIPHER_CTX_free(ctx);
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("Memory allocation failed."));
        return -1;
    }

    int len = 0, total = 0;
    if (EVP_EncryptUpdate(ctx, outbuf, &len, plaintext, (int)plaintext_len) != 1) {
        free(outbuf);
        EVP_CIPHER_CTX_free(ctx);
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("EncryptUpdate failed."));
        return -1;
    }
    total = len;
    if (EVP_EncryptFinal_ex(ctx, outbuf + total, &len) != 1) {
        free(outbuf);
        EVP_CIPHER_CTX_free(ctx);
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("EncryptFinal failed."));
        return -1;
    }
    total += len;

    unsigned char tag[TAG_SIZE];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag) != 1) {
        free(outbuf);
        EVP_CIPHER_CTX_free(ctx);
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("Get tag failed."));
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);

    *ciphertext = (unsigned char*)malloc(SALT_SIZE + IV_SIZE + TAG_SIZE + total);
    if (!*ciphertext) {
        free(outbuf);
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("Memory allocation failed."));
        return -1;
    }
    memcpy(*ciphertext, salt, SALT_SIZE);
    memcpy(*ciphertext + SALT_SIZE, iv, IV_SIZE);
    memcpy(*ciphertext + SALT_SIZE + IV_SIZE, tag, TAG_SIZE);
    memcpy(*ciphertext + SALT_SIZE + IV_SIZE + TAG_SIZE, outbuf, total);
    *ciphertext_len = SALT_SIZE + IV_SIZE + TAG_SIZE + total;
    free(outbuf);

    SecureZeroMemory(key, KEY_SIZE);
    ret = 0;
    return ret;
#endif
}

// Function to decrypt data
int decrypt_data(unsigned char* ciphertext, size_t ciphertext_len, const TCHAR* password,
    unsigned char** plaintext, size_t* plaintext_len) {
    if (ciphertext_len < SALT_SIZE + IV_SIZE + TAG_SIZE) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("An error occurred during decryption."));
        return -1;
    }

#ifdef _WIN32
    NTSTATUS status;
    int ret = -1;

    unsigned char* salt = ciphertext;
    unsigned char* iv = ciphertext + SALT_SIZE;
    unsigned char* tag = ciphertext + SALT_SIZE + IV_SIZE;
    unsigned char* enc_data = ciphertext + SALT_SIZE + IV_SIZE + TAG_SIZE;
    size_t enc_data_len = ciphertext_len - SALT_SIZE - IV_SIZE - TAG_SIZE;

    if (enc_data_len == 0) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("An error occurred during decryption."));
        return -1;
    }

    unsigned char key[KEY_SIZE];
    unsigned char derived_iv[IV_SIZE];
    if (derive_key_iv(password, salt, key, derived_iv) != 0) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("An error occurred during decryption."));
        return -1;
    }

    BCRYPT_ALG_HANDLE hAlg = NULL;
    if (!BCRYPT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("An error occurred during decryption."));
        return -1;
    }

    if (!BCRYPT_SUCCESS(status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0))) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("An error occurred during decryption."));
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD keyObjectSize = 0;
    DWORD result = 0;
    if (!BCRYPT_SUCCESS(status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjectSize, sizeof(DWORD), &result, 0))) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("An error occurred during decryption."));
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    PUCHAR keyObject = (PUCHAR)malloc(keyObjectSize);
    if (keyObject == NULL) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("An error occurred during decryption."));
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    if (!BCRYPT_SUCCESS(status = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObject, keyObjectSize, key, KEY_SIZE, 0))) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("An error occurred during decryption."));
        free(keyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = iv;
    authInfo.cbNonce = IV_SIZE;
    authInfo.pbTag = tag;
    authInfo.cbTag = TAG_SIZE;
    authInfo.pbAuthData = NULL;
    authInfo.cbAuthData = 0;

    *plaintext_len = enc_data_len;
    *plaintext = (unsigned char*)malloc(*plaintext_len);
    if (*plaintext == NULL) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("An error occurred during decryption."));
        BCryptDestroyKey(hKey);
        free(keyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }

    ULONG cbResult = 0;
    __try {
        if (!BCRYPT_SUCCESS(status = BCryptDecrypt(hKey, enc_data, (ULONG)enc_data_len, &authInfo, NULL, 0, *plaintext, (ULONG)*plaintext_len, &cbResult, 0))) {
            _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("An error occurred during decryption."));
            free(*plaintext);
            *plaintext = NULL;
            BCryptDestroyKey(hKey);
            free(keyObject);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return -1;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("An error occurred during decryption."));
        free(*plaintext);
        *plaintext = NULL;
        BCryptDestroyKey(hKey);
        free(keyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }
    *plaintext_len = cbResult;

    BCryptDestroyKey(hKey);
    free(keyObject);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    SecureZeroMemory(key, KEY_SIZE);

    ret = 0;
    return ret;
#else
    int ret = -1;
    const unsigned char* salt = ciphertext;
    const unsigned char* iv = ciphertext + SALT_SIZE;
    const unsigned char* tag = ciphertext + SALT_SIZE + IV_SIZE;
    const unsigned char* enc_data = ciphertext + SALT_SIZE + IV_SIZE + TAG_SIZE;
    size_t enc_data_len = ciphertext_len - SALT_SIZE - IV_SIZE - TAG_SIZE;

    if (enc_data_len == 0) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("An error occurred during decryption."));
        return -1;
    }

    unsigned char key[KEY_SIZE];
    unsigned char derived_iv[IV_SIZE];
    if (derive_key_iv(password, (unsigned char*)salt, key, derived_iv) != 0) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("An error occurred during decryption."));
        return -1;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("Cipher context allocation failed."));
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("DecryptInit failed."));
        return -1;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("Set IV length failed."));
        return -1;
    }
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("DecryptInit key/iv failed."));
        return -1;
    }

    *plaintext = (unsigned char*)malloc(enc_data_len);
    if (!*plaintext) {
        EVP_CIPHER_CTX_free(ctx);
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("Memory allocation failed."));
        return -1;
    }
    int len = 0, total = 0;
    if (EVP_DecryptUpdate(ctx, *plaintext, &len, enc_data, (int)enc_data_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*plaintext);
        *plaintext = NULL;
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("DecryptUpdate failed."));
        return -1;
    }
    total = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (void*)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*plaintext);
        *plaintext = NULL;
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("Set tag failed."));
        return -1;
    }
    if (EVP_DecryptFinal_ex(ctx, *plaintext + total, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*plaintext);
        *plaintext = NULL;
        _tcscpy_s(encryption_error_message, _countof(encryption_error_message), _T("An error occurred during decryption."));
        return -1;
    }
    total += len;
    *plaintext_len = total;
    EVP_CIPHER_CTX_free(ctx);
    SecureZeroMemory(key, KEY_SIZE);
    ret = 0;
    return ret;
#endif
}

// Function to derive key and IV
int derive_key_iv(const TCHAR* password, unsigned char* salt, unsigned char* key, unsigned char* iv) {
    int ret = -1;

#ifdef _WIN32
#ifdef UNICODE
    int password_len = (int)_tcslen(password);
    int utf8_len = WideCharToMultiByte(CP_UTF8, 0, password, password_len, NULL, 0, NULL, NULL);
    if (utf8_len <= 0) {
        return -1;
    }
    unsigned char* utf8_password = (unsigned char*)malloc(utf8_len);
    if (utf8_password == NULL) {
        return -1;
    }
    WideCharToMultiByte(CP_UTF8, 0, password, password_len, (LPSTR)utf8_password, utf8_len, NULL, NULL);
#else
    int utf8_len = (int)strlen(password);
    unsigned char* utf8_password = (unsigned char*)password;
#endif

    unsigned char derived[KEY_SIZE + IV_SIZE];
    if (pbkdf2_hmac_sha256(utf8_password, utf8_len, salt, SALT_SIZE, 100000, derived, KEY_SIZE + IV_SIZE) != 0) {
#ifdef UNICODE
        free(utf8_password);
#endif
        return -1;
    }

    memcpy(key, derived, KEY_SIZE);
    memcpy(iv, derived + KEY_SIZE, IV_SIZE);

#ifdef UNICODE
    SecureZeroMemory(utf8_password, utf8_len);
    free(utf8_password);
#endif

    ret = 0;
    return ret;
#else
    const unsigned char* pass_bytes = (const unsigned char*)password;
    int pass_len = (int)strlen(password);
    unsigned char derived[KEY_SIZE + IV_SIZE];
    if (PKCS5_PBKDF2_HMAC((const char*)pass_bytes, pass_len, salt, SALT_SIZE, 100000, EVP_sha256(), (int)(KEY_SIZE + IV_SIZE), derived) != 1) {
        return -1;
    }
    memcpy(key, derived, KEY_SIZE);
    memcpy(iv, derived + KEY_SIZE, IV_SIZE);
    ret = 0;
    return ret;
#endif
}

// PBKDF2-HMAC-SHA256 implementation
#ifdef _WIN32
int pbkdf2_hmac_sha256(const unsigned char* password, size_t password_len,
    const unsigned char* salt, size_t salt_len,
    unsigned int iterations, unsigned char* output, size_t output_len) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    if (!BCRYPT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG))) {
        return -1;
    }
    if (!BCRYPT_SUCCESS(status = BCryptDeriveKeyPBKDF2(hAlg, (PUCHAR)password, (ULONG)password_len, (PUCHAR)salt, (ULONG)salt_len, iterations, output, (ULONG)output_len, 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -1;
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return 0;
}
#endif

// Function to generate HMAC
int generate_hmac(const TCHAR* password, unsigned char* data, size_t data_len, unsigned char* hmac_output) {
#ifdef _WIN32
    NTSTATUS status;
    int ret = -1;

#ifdef UNICODE
    int password_len = (int)_tcslen(password);
    int utf8_len = WideCharToMultiByte(CP_UTF8, 0, password, password_len, NULL, 0, NULL, NULL);
    if (utf8_len <= 0) {
        return -1;
    }
    unsigned char* utf8_password = (unsigned char*)malloc(utf8_len);
    if (utf8_password == NULL) {
        return -1;
    }
    WideCharToMultiByte(CP_UTF8, 0, password, password_len, (LPSTR)utf8_password, utf8_len, NULL, NULL);
#else
    int utf8_len = (int)strlen(password);
    unsigned char* utf8_password = (unsigned char*)password;
#endif

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;

    if (!BCRYPT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG))) {
#ifdef UNICODE
        free(utf8_password);
#endif
        return -1;
    }

    DWORD hashObjectSize = 0;
    DWORD result = 0;
    if (!BCRYPT_SUCCESS(status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hashObjectSize, sizeof(DWORD), &result, 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
#ifdef UNICODE
        free(utf8_password);
#endif
        return -1;
    }

    PUCHAR hashObject = (PUCHAR)malloc(hashObjectSize);
    if (hashObject == NULL) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
#ifdef UNICODE
        free(utf8_password);
#endif
        return -1;
    }

    if (!BCRYPT_SUCCESS(status = BCryptCreateHash(hAlg, &hHash, hashObject, hashObjectSize, utf8_password, utf8_len, 0))) {
        free(hashObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
#ifdef UNICODE
        free(utf8_password);
#endif
        return -1;
    }

    if (!BCRYPT_SUCCESS(status = BCryptHashData(hHash, data, (ULONG)data_len, 0))) {
        BCryptDestroyHash(hHash);
        free(hashObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
#ifdef UNICODE
        free(utf8_password);
#endif
        return -1;
    }

    if (!BCRYPT_SUCCESS(status = BCryptFinishHash(hHash, hmac_output, 32, 0))) {
        BCryptDestroyHash(hHash);
        free(hashObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
#ifdef UNICODE
        free(utf8_password);
#endif
        return -1;
    }

    BCryptDestroyHash(hHash);
    free(hashObject);
    BCryptCloseAlgorithmProvider(hAlg, 0);

#ifdef UNICODE
    SecureZeroMemory(utf8_password, utf8_len);
    free(utf8_password);
#endif

    ret = 0;
    return ret;
#else
    const unsigned char* pass_bytes = (const unsigned char*)password;
    int pass_len = (int)strlen(password);
    unsigned int out_len = 0;
    unsigned char* result = HMAC(EVP_sha256(), pass_bytes, pass_len, data, (int)data_len, hmac_output, &out_len);
    return (result != NULL && out_len == 32) ? 0 : -1;
#endif
}
