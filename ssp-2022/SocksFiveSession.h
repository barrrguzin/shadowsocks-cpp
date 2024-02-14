#pragma once
#include <WinSock2.h>
#include "RemoteConnection.h"
#include "ClientConnection.h"
#include "ProxySession.h"

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
	virtual int handleSocksProxyHandShacke();
	virtual int clientToRemoteServerHandler();
	virtual int remoteServerToClientHandler();

public:
	int startProxySession();
	SocksFiveSession(std::shared_ptr<ClientConnection> clientConnection, std::shared_ptr<RemoteConnection> serverSideSocket, std::shared_ptr<spdlog::logger> logger);
	~SocksFiveSession();
};

