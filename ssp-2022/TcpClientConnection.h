#pragma once
#include "ClientConnection.h"
#include <WinSock2.h>
#include <iostream>

#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"


class TcpClientConnection : public ClientConnection
{
private:
	std::shared_ptr<spdlog::logger> logger;

public:
	int sendTo(char message[], int messageSize);
	int recieveFrom(char message[], int messageSize);
	int closeConnection();
	SOCKET& getRawSocket();

	TcpClientConnection(std::shared_ptr<SOCKET> clientConnection, std::shared_ptr<spdlog::logger> logger);
	~TcpClientConnection();
};

