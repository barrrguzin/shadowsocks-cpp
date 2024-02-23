#include "TcpClientConnection.h"

#include "cryptlib.h"
#include "filters.h"
#include "files.h"
#include "hex.h"
#include <memory>


using namespace CryptoPP;

TcpClientConnection::TcpClientConnection(boost::asio::ip::tcp::socket* clientConnection, std::shared_ptr<spdlog::logger> logger) : ClientConnection()
{
	this->logger = logger;
	this->clientSock = clientConnection;
}

TcpClientConnection::~TcpClientConnection()
{
	this->ClientConnection::~ClientConnection();
}

boost::asio::awaitable<unsigned long long> TcpClientConnection::sendTo(char message[], int messageSize)
{
	//Sleep(50);
	return boost::asio::async_write(*clientSock, boost::asio::buffer(message, messageSize), boost::asio::use_awaitable);
	//return send(*clientConnection, message, messageSize, NULL);
}

boost::asio::awaitable<unsigned long long> TcpClientConnection::recieveFrom(char message[], int messageSize)
{
	try
	{
		boost::system::error_code error;
		this->logger->debug("RECV...");
		return boost::asio::async_read(*clientSock, boost::asio::buffer(message, messageSize), boost::asio::use_awaitable);
		/*
		if (error && error != boost::asio::error::eof) {
			this->logger->error("{} receive failed: {}", error.value(), error.message());
			return -1;
		}
		this->logger->error("RECVD");
		return x;
		*/
	}
	catch (Exception e)
	{
		this->logger->error("RECV#");
	}
	//return recv(*clientConnection, message, messageSize, NULL);
}

int TcpClientConnection::closeConnection()
{
	//closesocket(*clientConnection);
	WSACleanup();
	this->logger->debug("Client closed...");
	return 0;
}