#pragma once

#include "Connection.h"
#include <WinSock2.h>
#include <memory>

class ClientConnection : public Connection
{
public:

	std::shared_ptr<SOCKET> clientConnection;

	SOCKET& getRawSocket()
	{
		return *clientConnection;
	}
	/*
	ClientConnection(std::shared_ptr<SOCKET> clientConnection)
	{
		this->clientConnection = clientConnection;
	}
	*/
	ClientConnection() {}

	~ClientConnection()
	{
		//closesocket(*clientConnection);
	}
};

