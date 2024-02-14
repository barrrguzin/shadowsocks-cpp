#pragma once

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "CryptoProviderAEAD.h"

#include "cryptlib.h"
#include "chachapoly.h"
#include "filters.h"
#include "files.h"
#include "hex.h"
#include "md5.h"
#include "hkdf.h"
#include "sha.h"

#include <sodium.h>
#include <mutex>

#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/fmt/bin_to_hex.h"



using namespace CryptoPP;

class ShadowSocksChaCha20Poly1305 : public CryptoProviderAEAD
{
public:
    int encrypt(byte* encryptedMessage, byte* plainText, const short int sizeOfPlainText);
    int encrypt(char* encryptedMessage, byte* plainText, const short int sizeOfPlainText);

    int decrypt(byte* recoveredMessage, byte* encryptedPackage, const short int sizeOfEncryptedPackage);
    int decrypt(byte* recoveredMessage, char* encryptedPackage, const short int sizeOfEncryptedPackage);

    int prepareSubSessionKey(SimpleKeyingInterface* ski, byte* salt);
    SimpleKeyingInterface* getEncryptor();
    SimpleKeyingInterface* getDecryptor();

    ShadowSocksChaCha20Poly1305(byte* password, int sizeOfPassword, std::shared_ptr<spdlog::logger> logger);
    ~ShadowSocksChaCha20Poly1305();

private:
    std::mutex _mutex;
    std::shared_ptr<spdlog::logger> logger;

    void incrementNonce(byte* iv, short int nonceLength);

    //int decryptNext(byte* recoveredMessage, byte* encryptedPackage, const short int sizeOfEncryptedPackage);

    ChaCha20Poly1305::Encryption encryptor;
    ChaCha20Poly1305::Decryption decryptor;
    HKDF<SHA1> hkdf;

    static const int OPENSSL_PKCS5_SALT_LEN = 8;

    static const int ENCRYPTED_PAYLOAD_LENGTH = 2;

    static const int INFO_LENGTH = 9;
    //static constexpr const byte INFO[32] = { 0x73, 0x73, 0x2d, 0x73, 0x75, 0x62, 0x6b, 0x65, 0x79 };
    byte INFO[INFO_LENGTH] = { 0x73, 0x73, 0x2d, 0x73, 0x75, 0x62, 0x6b, 0x65, 0x79 };

    static const int SALT_LENGTH = 32;
    //const byte* salt[SALT_LENGTH];
	
    static const int AAD_LENGTH = 16;

    static const int IV_LENGTH = 12;//NONCE
    byte encryptionIV[IV_LENGTH] = { 0 };
    byte decryptionIV[IV_LENGTH] = { 0 };

    static const int TAG_LENGTH = 16;//MAC
    //byte* tag[TAG_LENGTH];

    static const int KEY_LENGTH = 32;
    byte key[KEY_LENGTH];

    byte decryptionSubSessionKey[KEY_LENGTH];
    

    int OPENSSL_EVP_BytesToKey(HashTransformation& hash,
        const unsigned char* salt, const unsigned char* data, int dlen,
        unsigned int count, unsigned char* key, unsigned int ksize,
        unsigned char* iv, unsigned int vsize);
};
