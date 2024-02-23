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

boost::asio::awaitable<void> ShadowSocksSession::startProxySession(char* firstDataToRemote, const short int firstDataToRemoteLength)
{
	try
	{
		if (this->remoteConnection != nullptr)
		{
			//send payload to remote server
			remoteConnection->sendTo(firstDataToRemote, firstDataToRemoteLength);

			const auto executor = co_await boost::asio::this_coro::executor;
			boost::asio::co_spawn(executor, clientToRemoteServerHandler(), boost::asio::detached);
			boost::asio::co_spawn(executor, remoteServerToClientHandler(), boost::asio::detached);


			this->logger->debug("ShadowSocks session started...");
			delete firstDataToRemote;

		}
		else
		{

		}
	}
	catch (Exception e)
	{
		this->logger->critical("Exception caught during starting proxy session...");
	}
}

ShadowSocksSession::ShadowSocksSession(std::shared_ptr<ClientConnection> clientConnection, std::shared_ptr<RemoteConnection> remoteConnection, std::shared_ptr<CryptoProvider> cryptoProvider, std::shared_ptr<spdlog::logger> logger) : SocksFiveSession()
{
	try
	{
		this->logger = logger;
		this->logger->critical("1");
		this->cryptoProvider = cryptoProvider;
		this->clientConnection = clientConnection;
		this->remoteConnection = remoteConnection;
		char* recovered = new char[socksSessionBufferSize + 100];
		//char recovered[socksSessionBufferSize];
		this->logger->critical("2");
		int recoveredDataLength = handleSocksProxyHandShacke(recovered, socksSessionBufferSize).await_resume();
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
	catch (Exception e)
	{
		this->logger->critical("Exception caught during creating session...");
	}
	
}

ShadowSocksSession::~ShadowSocksSession()
{
	//this->SocksFiveSession::~SocksFiveSession();
}


boost::asio::awaitable<int> ShadowSocksSession::handleSocksProxyHandShacke(char* recievedData, const short int recievedDataLength)
{
	this->logger->critical("3");
	int firstRecievedMessageLength = co_await clientConnection->recieveFrom(clientToRemoteServerBuffer, socksSessionBufferSize);
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
					co_return recoveredPayloadLength;
				}
			}
		}
	}
	co_return -1;
}


//[salt][encrypted payload length][length tag][encrypted payload][payload tag]
// 0 - [salt] = 32
// 1 - [encrypted payload length][length tag] = [2][16]
// 2 - [encrypted payload][payload tag] = [decrypted payload length][16]
//http://rose-engine.org/press/signalis/images/header.png
//http://rose-engine.org/press/signalis/images/SIGNALIS%20Elster%204.png
//http://rose-engine.org/press/signalis/images/SIGNALIS%20Ariane.png
boost::asio::awaitable<int> ShadowSocksSession::handleSocksProxyHandShacke()
{
	co_return 0;
}

boost::asio::awaitable<void> ShadowSocksSession::clientToRemoteServerHandler()
{
	try
	{
		char recoveredChars[socksSessionBufferSize];
		byte* recoveredBytes = reinterpret_cast<byte*>(recoveredChars);
		while (backToBackConectionState)
		{
			int recived = co_await clientConnection->recieveFrom(clientToRemoteServerBuffer, socksSessionBufferSize);
			this->logger->critical("Recieve {} bytes...", recived);
			int recoveredDataLength = cryptoProvider->decrypt(recoveredBytes, clientToRemoteServerBuffer, recived);
			if (recived > 0 && recoveredDataLength > 0)
			{
				if (remoteConnection->sendTo(recoveredChars, recoveredDataLength).await_resume() == -1)
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
	}
	catch (Exception e)
	{
		this->logger->critical("Exception caught in clientToRemoteServerHandler()...");
	}	
}

boost::asio::awaitable<void> ShadowSocksSession::remoteServerToClientHandler()
{

	try
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
			int recived = co_await remoteConnection->recieveFrom(remoteServerToClientBuffer, socksSessionBufferSize);

			if (recived > 0)
			{
				int encryptedMessageLength = cryptoProvider->encrypt(&encrypted[diff], palinTextByte, recived);
				if (clientConnection->sendTo(encrypted, encryptedMessageLength + diff).await_resume() == -1)
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
	}
	catch (Exception e)
	{
		this->logger->critical("Exception caught in remoteServerToClientHandler()...");
	}
}


