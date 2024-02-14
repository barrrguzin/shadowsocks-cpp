#pragma once

#include "SocksFiveSession.h"
#include "CryptoProvider.h"
#include "RemoteConnection.h"
#include "ClientConnection.h"

#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/fmt/bin_to_hex.h"

class ShadowSocksSession : public SocksFiveSession
{
protected:
	static const short int MAX_PAYLOAD_LENGTH = 16383;
	static const short int MAX_PACKAGE_LENGTH = 32+2+16+16383+16;

	//char clientToRemoteServerBuffer1[socksSessionBufferSize + 100];
	//char remoteServerToClientBuffer1[socksSessionBufferSize + 100];

	std::array<char, socksSessionBufferSize + 100> clientToRemoteServerBuffer1;
	std::array<char, socksSessionBufferSize + 100> remoteServerToClientBuffer1;


private:
	std::shared_ptr<spdlog::logger> logger;
	std::mutex _mutex;

	int handleSocksProxyHandShacke();
	int handleSocksProxyHandShacke(char* recievedData, const short int recievedDataLength);
	int clientToRemoteServerHandler();
	int remoteServerToClientHandler();

	std::shared_ptr<CryptoProvider> cryptoProvider;

	int OPENSSL_EVP_BytesToKey(HashTransformation& hash,
		const unsigned char* salt, const unsigned char* data, int dlen,
		unsigned int count, unsigned char* key, unsigned int ksize,
		unsigned char* iv, unsigned int vsize);

public:
	int startProxySession(char* firstDataToRemote, const short int firstDataToRemoteLength);
	int startProxySession();
	
	ShadowSocksSession(std::shared_ptr<ClientConnection> clientConnection, std::shared_ptr<RemoteConnection> serverSideSocket, std::shared_ptr<CryptoProvider> cryptoProvider, std::shared_ptr<spdlog::logger> logger);
	~ShadowSocksSession();



};

