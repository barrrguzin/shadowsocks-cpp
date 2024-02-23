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
	boost::asio::ip::tcp::socket* clientSock;

public:
	boost::asio::awaitable<unsigned long long> sendTo(char message[], int messageSize);
	boost::asio::awaitable<unsigned long long> recieveFrom(char message[], int messageSize);
	int closeConnection();
	SOCKET& getRawSocket();
	TcpClientConnection();
	TcpClientConnection(boost::asio::ip::tcp::socket* clientConnection, std::shared_ptr<spdlog::logger> logger);
	~TcpClientConnection();
};

