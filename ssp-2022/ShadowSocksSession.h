#pragma once

#include "SocksFiveSession.h"
#include "CryptoProvider.h"
#include "RemoteConnection.h"
#include "ClientConnection.h"

#include <boost/asio/io_context.hpp>
#include <boost/asio/execution/executor.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/ip/tcp.hpp>

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

	boost::asio::awaitable<int> handleSocksProxyHandShacke();
	boost::asio::awaitable<int> handleSocksProxyHandShacke(char* recievedData, const short int recievedDataLength);
	boost::asio::awaitable<void> clientToRemoteServerHandler();
	boost::asio::awaitable<void> remoteServerToClientHandler();

	std::shared_ptr<CryptoProvider> cryptoProvider;

	int OPENSSL_EVP_BytesToKey(HashTransformation& hash,
		const unsigned char* salt, const unsigned char* data, int dlen,
		unsigned int count, unsigned char* key, unsigned int ksize,
		unsigned char* iv, unsigned int vsize);

public:
	boost::asio::awaitable<void> startProxySession(char* firstDataToRemote, const short int firstDataToRemoteLength);
	int startProxySession();
	
	ShadowSocksSession(std::shared_ptr<ClientConnection> clientConnection, std::shared_ptr<RemoteConnection> serverSideSocket, std::shared_ptr<CryptoProvider> cryptoProvider, std::shared_ptr<spdlog::logger> logger);
	~ShadowSocksSession();



};

