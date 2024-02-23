#include "SocksFiveSession.h"

SocksFiveSession::SocksFiveSession()
{}

SocksFiveSession::SocksFiveSession(std::shared_ptr<ClientConnection> clientConnection, std::shared_ptr<RemoteConnection> serverSideSocket, std::shared_ptr<spdlog::logger> logger)
{
	this->clientConnection = clientConnection;
	this->remoteConnection = serverSideSocket;

	if (handleSocksProxyHandShacke().await_resume() == 0)
	{
		const char* addressBytes = ((this->address)).c_str();
		if (this->remoteConnection->initializeServerSideSocket(addressBytes, port) == 0)
		{
			if (this->remoteConnection->startConnectionToServer() == 0)
			{
				this->logger->debug("Socks5 session initialized: {}:{}", (this->address), this->port);
			}
			else
			{
				this->logger->debug("Unable to initialize Socks5 sessio...");
			}
		}
		else
		{
			this->logger->debug("Unable to initialize Socks5 sessio...");
		}
		
	}
}

SocksFiveSession::~SocksFiveSession()
{
	if (this != nullptr && this->logger != nullptr)
	{
		this->logger->debug("Socks5 session released...");
	}
}

boost::asio::awaitable<int> SocksFiveSession::handleSocksProxyHandShacke()
{
	int recived = co_await clientConnection->recieveFrom(initialPackage, sizeOfInitialPackage);
	if (recived == sizeOfInitialPackage)
	{
		clientConnection->sendTo((char*) initialPackageAnswer, sizeOfInitialPackageAnswer);
		char remoteHostAddressBuffer[310];
		int recived = co_await clientConnection->recieveFrom(remoteHostAddressBuffer, sizeof(remoteHostAddressBuffer));
		if (recived > 0)
		{
			char* address = &remoteHostAddressBuffer[5];
			char* port = &remoteHostAddressBuffer[recived - 2];

			this->address = std::string(address, recived - 7);
			char revPort[2];
			revPort[0] = port[1];
			revPort[1] = port[0];
			std::memcpy(&(this->port), revPort, 2);
			clientConnection->sendTo((char*) handShakeDoneResponse, handShakeDoneResponseSize);
			co_return 0;
		}
		else
		{
			this->logger->debug("Unable to get destination address from client...");
			co_return -1;
		}
	}
	else
	{
		this->logger->debug("Unable to handle hello message...");
		co_return -1;
	}
}

int SocksFiveSession::startProxySession()
{
	if (this->remoteConnection != nullptr)
	{
		//std::thread remoteServerToClientThread(&SocksFiveSession::remoteServerToClientHandler, this);
		//std::thread clientToRemoteServerThread(&SocksFiveSession::clientToRemoteServerHandler, this);

		//remoteServerToClientThread.join();
		//clientToRemoteServerThread.join();
		return 0;
	}
	else
	{
		return 1;
	}
}
/*
boost::asio::awaitable<void> SocksFiveSession::clientToRemoteServerHandler()
{
	while (backToBackConectionState) {
		
		int recived = clientConnection->recieveFrom(clientToRemoteServerBuffer, socksSessionBufferSize);
		if (recived > 0)
		{
			remoteConnection->sendTo(clientToRemoteServerBuffer, recived);
		}
		else
		{
			backToBackConectionState = false;
		}
		//Sleep(1);
	}
	this->logger->debug("Client drop connection... Exit");
	return;
}

boost::asio::awaitable<void> SocksFiveSession::remoteServerToClientHandler()
{
	while (backToBackConectionState) 
	{
		int recived = remoteConnection->recieveFrom(remoteServerToClientBuffer, socksSessionBufferSize);
		if (recived > 0)
		{
			clientConnection->sendTo(remoteServerToClientBuffer, recived);
		}
		else
		{
			backToBackConectionState = false;
		}
		//Sleep(5);
	}
	this->logger->debug("Server drop connection... Exit");
	return;
}
*/