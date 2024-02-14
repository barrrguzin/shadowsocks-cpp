#include "TcpRemoteConnection.h"

TcpRemoteConnection::TcpRemoteConnection(std::shared_ptr<spdlog::logger> logger) 
{
	this->logger = logger;
}

TcpRemoteConnection::~TcpRemoteConnection()
{
	closeConnection();
}

int TcpRemoteConnection::initializeServerSideSocket(const char* targetAddress, int targetPort)
{
	TcpRemoteConnection::targetAddress = targetAddress;
	TcpRemoteConnection::targetPort = targetPort;
	if (WSAStartup(DLLVersion, &wsaData) != 0)
	{
		this->logger->error("WSA initialization error...");
		return -1;
	}
	
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	std::string s = std::to_string(targetPort);
	char const* pchar = s.c_str();
	return getaddrinfo(targetAddress, pchar, &hints, &addrs);
}

int TcpRemoteConnection::startConnectionToServer()
{
	connection = socket(addrs->ai_family, addrs->ai_socktype, addrs->ai_protocol);
	if (connect(connection, addrs->ai_addr, addrs->ai_addrlen) != 0)
	{
		this->logger->error("Server side connection error...");
		return -1;
	}
	this->logger->debug("Connection to remote server started: {}:{}", this->targetAddress, this->targetPort);
	return 0;
}

int TcpRemoteConnection::sendTo(char message[], int messageSize)
{
	//Sleep(50);
	return send(connection, message, messageSize, NULL);
}

int TcpRemoteConnection::recieveFrom(char message[], int messageSize)
{
	//Sleep(50);
	return recv(connection, message, messageSize, NULL);
}

int TcpRemoteConnection::closeConnection()
{
	closesocket(connection);
	WSACleanup();
	this->logger->debug("Server side socket closed: {}:{}", this->targetAddress, this->targetPort);
	return 0;
}