#include "TcpClientConnection.h"

#include "cryptlib.h"
#include "filters.h"
#include "files.h"
#include "hex.h"
#include <memory>

using namespace CryptoPP;

TcpClientConnection::TcpClientConnection(std::shared_ptr<SOCKET> clientConnection, std::shared_ptr<spdlog::logger> logger) : ClientConnection()
{
	this->logger = logger;
	this->clientConnection = clientConnection;
}

TcpClientConnection::~TcpClientConnection()
{
	this->ClientConnection::~ClientConnection();
}

int TcpClientConnection::sendTo(char message[], int messageSize)
{
	//Sleep(50);
	return send(*clientConnection, message, messageSize, NULL);
}

int TcpClientConnection::recieveFrom(char message[], int messageSize)
{
	//Sleep(50);
	return recv(*clientConnection, message, messageSize, NULL);
}

int TcpClientConnection::closeConnection()
{
	closesocket(*clientConnection);
	WSACleanup();
	this->logger->debug("Client closed...");
	return 0;
}