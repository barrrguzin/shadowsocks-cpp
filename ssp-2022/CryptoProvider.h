#pragma once

#include "cryptlib.h"

using namespace CryptoPP;

class CryptoProvider
{
protected:
	virtual void incrementNonce(byte* iv, short int nonceLength) = 0;
	
public:
	virtual int encrypt(byte* encryptedMessage, byte* plainText, const short int sizeOfPlainText) = 0;
	virtual int encrypt(char* encryptedMessage, byte* plainText, const short int sizeOfPlainText) = 0;

	virtual int decrypt(byte* recoveredMessage, byte* encryptedPackage, const short int sizeOfEncryptedPackage) = 0;
	virtual int decrypt(byte* recoveredMessage, char* encryptedPackage, const short int sizeOfEncryptedPackage) = 0;

	virtual int prepareSubSessionKey(SimpleKeyingInterface* ski, byte* salt) = 0;

	virtual SimpleKeyingInterface* getEncryptor() = 0;
	virtual SimpleKeyingInterface* getDecryptor() = 0;
};