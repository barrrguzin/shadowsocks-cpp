#pragma once
#include <WinSock2.h>
#include "RemoteConnection.h"
#include "ClientConnection.h"
#include "ProxySession.h"

#include <boost/asio/io_context.hpp>
#include <boost/asio/execution/executor.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "spdlog/spdlog.h"

class SocksFiveSession : public ProxySession
{
private:
	std::shared_ptr<spdlog::logger> logger;

protected:
	SocksFiveSession();


	std::atomic<bool> backToBackConectionState = true;
	static const int sizeOfInitialPackage = 3;
	static constexpr char initialPackageSample[sizeOfInitialPackage] = { 0x05, 0x01, 0x00 };
	static const int sizeOfInitialPackageAnswer = 2;
	static constexpr char initialPackageAnswer[sizeOfInitialPackageAnswer] = { 0x05, 0x00 };
	static const int handShakeDoneResponseSize = 10;
	static constexpr char handShakeDoneResponse[handShakeDoneResponseSize] = { 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	char initialPackage[sizeOfInitialPackage];
	std::string address;
	int port;
	static const int socksSessionBufferSize = 1350;//1420
	char clientToRemoteServerBuffer[socksSessionBufferSize+100];
	char remoteServerToClientBuffer[socksSessionBufferSize+100];
	
	std::shared_ptr<ClientConnection> clientConnection;
	std::shared_ptr<RemoteConnection> remoteConnection;
	virtual boost::asio::awaitable<int> handleSocksProxyHandShacke();
	/*
	virtual boost::asio::awaitable<void> clientToRemoteServerHandler();
	virtual boost::asio::awaitable<void> remoteServerToClientHandler();
	*/
public:
	int startProxySession();
	SocksFiveSession(std::shared_ptr<ClientConnection> clientConnection, std::shared_ptr<RemoteConnection> serverSideSocket, std::shared_ptr<spdlog::logger> logger);
	~SocksFiveSession();
};

