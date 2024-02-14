#pragma once
#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable: 4996)

#include "RemoteConnection.h"

#include <WinSock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <thread>
#include <string>
#include <vector>

#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"

class TcpRemoteConnection : public RemoteConnection
{
protected:
	const char* targetAddress;
	int targetPort;

private:
	std::shared_ptr<spdlog::logger> logger;

	WSAData wsaData;
	WORD DLLVersion = MAKEWORD(2, 1);

	//SOCKADDR_IN addr;
	struct addrinfo hints = { 0 }, * addrs;
	SOCKET connection;
	int sizeofaddr = 0;

public:
	TcpRemoteConnection(std::shared_ptr<spdlog::logger> logger);
	int initializeServerSideSocket(const char* targetAddress, int targetPort);
	int startConnectionToServer();
	SOCKET& getRawSocket();

	~TcpRemoteConnection();
	
	int sendTo(char message[], int messageSize);
	int recieveFrom(char message[], int messageSize);

	
	int closeConnection();
};

