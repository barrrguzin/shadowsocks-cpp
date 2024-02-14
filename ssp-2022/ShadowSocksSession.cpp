#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "ShadowSocksSession.h"

#include "ShadowSocksChaCha20Poly1305.h"




#include <bitset>
#include <gcm.h>
#include <rijndael.h>
#include "aes.h"
#include <sodium.h>
#include <ws2tcpip.h>
#include "scrypt.h"
#include "md5.h"
#include "hkdf.h"
#include "sha.h"


#include <future>


int ShadowSocksSession::startProxySession()
{
	return 0;
}

int ShadowSocksSession::startProxySession(char* firstDataToRemote, const short int firstDataToRemoteLength)
{
	if (this->remoteConnection != nullptr)
	{
		//send payload to remote server
		remoteConnection->sendTo(firstDataToRemote, firstDataToRemoteLength);
		std::thread clientToRemoteServerThread(&ShadowSocksSession::clientToRemoteServerHandler, this);
		std::thread remoteServerToClientThread(&ShadowSocksSession::remoteServerToClientHandler, this);
		this->logger->debug("ShadowSocks session started...");
		delete firstDataToRemote;
		clientToRemoteServerThread.join();
		remoteServerToClientThread.join();
		
		return 0;
	}
	else
	{
		return -1;
	}
}

ShadowSocksSession::ShadowSocksSession(std::shared_ptr<ClientConnection> clientConnection, std::shared_ptr<RemoteConnection> remoteConnection, std::shared_ptr<CryptoProvider> cryptoProvider, std::shared_ptr<spdlog::logger> logger) : SocksFiveSession()
{
	this->logger = logger;
	this->cryptoProvider = cryptoProvider;
	this->clientConnection = clientConnection;
	this->remoteConnection = remoteConnection;
	char* recovered = new char[socksSessionBufferSize+100];
	//char recovered[socksSessionBufferSize];
	int recoveredDataLength = handleSocksProxyHandShacke(recovered, socksSessionBufferSize);
	if (recoveredDataLength > 0)
	{
		startProxySession(recovered, recoveredDataLength);
	}
	else
	{
		delete[] recovered;
		this->logger->warn("Unable to start ShadowSocks session...");
	}
}

ShadowSocksSession::~ShadowSocksSession()
{
	//this->SocksFiveSession::~SocksFiveSession();
}


int ShadowSocksSession::handleSocksProxyHandShacke(char* recievedData, const short int recievedDataLength)
{
	int firstRecievedMessageLength = clientConnection->recieveFrom(clientToRemoteServerBuffer, socksSessionBufferSize);
	this->logger->trace("Message recieved: {}", firstRecievedMessageLength);
	if (firstRecievedMessageLength > 0)
	{
		//recovered == recievedData
		byte* recovered = reinterpret_cast<byte*>(recievedData);
		//set laengt to forward pointer
		int firstMessageOverhead = 32 + 2 + 16 + 16;
		//get salt and set sub-session key
		byte* salt = reinterpret_cast<byte*>(clientToRemoteServerBuffer);
		cryptoProvider->prepareSubSessionKey(cryptoProvider->getDecryptor(), salt);
		//recover destination address
		byte* firstMessage = reinterpret_cast<byte*>(clientToRemoteServerBuffer + 32);
		int recoveredTargetAddressLength = cryptoProvider->decrypt(recovered, firstMessage, firstRecievedMessageLength-32);
		if (recoveredTargetAddressLength > 0)
		{
			//setup recovered address
			byte addressType = recovered[0];
			short addressLength = recovered[1];
			this->logger->trace("Recieved: {}; Target address length: {}; Address bytes: {:n}", recoveredTargetAddressLength, addressLength, spdlog::to_hex(recovered, recovered + recoveredTargetAddressLength));
			char* address = &recievedData[2];
			this->address = std::string(address, addressLength);
			byte swapArray[] = { recovered[addressLength + 2 + 1], recovered[addressLength + 2 + 0] };
			std::memcpy(&(this->port), swapArray, 2);
			//recover data message
			char mode = 's';
			byte* secondMessage = reinterpret_cast<byte*>(clientToRemoteServerBuffer + firstMessageOverhead + recoveredTargetAddressLength);
			int recoveredPayloadLength = cryptoProvider->decrypt(recovered, secondMessage, firstRecievedMessageLength - firstMessageOverhead - recoveredTargetAddressLength);
			
			/*
			if (mode == 's')
			{
				//shadowsocks-windows-csharp
				byte* secondMessage = reinterpret_cast<byte*>(clientToRemoteServerBuffer + firstMessageOverhead + recoveredTargetAddressLength);
				recoveredPayloadLength = cryptoProvider->decrypt(recovered, secondMessage, firstRecievedMessageLength - firstMessageOverhead - recoveredTargetAddressLength);
			}
			else if (mode == 'r')
			{
				//shadowsocks-2022-rust
				recoveredPayloadLength = recoveredTargetAddressLength - 2 - addressLength - 2;
				std::memcpy(recievedData, (recievedData + 2 + 2 + addressLength), recoveredPayloadLength);
			}	
			*/

			//initialize remote connection
			if (this->remoteConnection->initializeServerSideSocket(((this->address)).c_str(), this->port) == 0)
			{
				if (this->remoteConnection->startConnectionToServer() == 0)
				{
					return recoveredPayloadLength;
				}
			}
		}
	}
	return -1;
}


//[salt][encrypted payload length][length tag][encrypted payload][payload tag]
// 0 - [salt] = 32
// 1 - [encrypted payload length][length tag] = [2][16]
// 2 - [encrypted payload][payload tag] = [decrypted payload length][16]
//http://rose-engine.org/press/signalis/images/header.png
//http://rose-engine.org/press/signalis/images/SIGNALIS%20Elster%204.png
//http://rose-engine.org/press/signalis/images/SIGNALIS%20Ariane.png
int ShadowSocksSession::handleSocksProxyHandShacke()
{
	return 0;
}

int ShadowSocksSession::clientToRemoteServerHandler()
{
	char recoveredChars[socksSessionBufferSize];
	byte* recoveredBytes = reinterpret_cast<byte*>(recoveredChars);
	while (backToBackConectionState) 
	{
		int recived = clientConnection->recieveFrom(clientToRemoteServerBuffer, socksSessionBufferSize);
		this->logger->critical("Recieve {} bytes...", recived);
		int recoveredDataLength = cryptoProvider->decrypt(recoveredBytes, clientToRemoteServerBuffer, recived);
		if (recived > 0 && recoveredDataLength > 0)
		{
			if (remoteConnection->sendTo(recoveredChars, recoveredDataLength) == -1)
			{
				break;
			}
		}
		else
		{
			if (recoveredDataLength == 0 && recived > 0)
			{
				this->logger->warn("Decryption error... Recieved {} bytes, but can not decrypt it...", recived);
			}
			break;
		}
	}
	this->backToBackConectionState = false;
	this->logger->debug("Client drop connection...");
	return 0;	
}

int ShadowSocksSession::remoteServerToClientHandler()
{
	char encrypted[socksSessionBufferSize];
	byte SALT[32] = { 0 };
	char* SALTC = reinterpret_cast<char*>(SALT);
	byte* palinTextByte = reinterpret_cast<byte*>(remoteServerToClientBuffer);
	std::memcpy(encrypted, SALTC, 32);
	cryptoProvider->prepareSubSessionKey(cryptoProvider->getEncryptor(), SALT);
	int diff = 32;
	while (backToBackConectionState)
	{
		int recived = remoteConnection->recieveFrom(remoteServerToClientBuffer, socksSessionBufferSize);

		if (recived > 0)
		{
			int encryptedMessageLength = cryptoProvider->encrypt(&encrypted[diff], palinTextByte, recived);
			if (clientConnection->sendTo(encrypted, encryptedMessageLength + diff) == -1)
			{
				break;
			}
			diff = 0;
		}
		else
		{
			break;
		}
	}
	this->backToBackConectionState = false;
	this->logger->debug("Remote server drop connection...");
	return 0;
}


