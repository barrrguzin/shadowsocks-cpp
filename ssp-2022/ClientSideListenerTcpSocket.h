#pragma once
#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable: 4996)

#include "SocksFiveSession.h"
#include "ClientSideListenerSocket.h"
#include "RemoteConnection.h"
#include "ClientConnection.h"
#include "TcpRemoteConnection.h"
#include "TcpClientConnection.h"
#include "ShadowSocksSession.h"
#include "CryptoProvider.h"
#include "ShadowSocksChaCha20Poly1305.h"

#include <WinSock2.h>
#include <iostream>
#include <thread>
#include <string>
#include <vector>

#include "spdlog/spdlog.h"


class ClientSideListenerTcpSocket : public ClientSideListenerSocket
{
protected:
	char* listeningAddress;
	int listeningPort;

private:
	std::shared_ptr<spdlog::logger> logger;

	void (ClientSideListenerTcpSocket::*clientHandler)(std::shared_ptr<SOCKET>);

	void socksFiveClientHandler(std::shared_ptr<SOCKET> acceptedConnection);
	void shadowSocksClientHandler(std::shared_ptr<SOCKET> acceptedConnection);

	void handleConnections();

	WSAData wsaData;
	WORD DLLVersion = MAKEWORD(2, 1);
	std::shared_ptr<CryptoProvider> cryptoProvider;

	SOCKADDR_IN addr;
	SOCKET sListener;
	int sizeofaddr = 0;

	int closeListener();

	int handleSocksHandShake(SOCKET& acceptedConnection);


	unsigned char* stringToUnsignedCharArray(std::string str);



	

public:
	int startListener();
	
	ClientSideListenerTcpSocket(char* listeningAddress, int listeningPort, std::shared_ptr<spdlog::logger> logger, std::shared_ptr<CryptoProvider> cryptoProvider);
	~ClientSideListenerTcpSocket();
};