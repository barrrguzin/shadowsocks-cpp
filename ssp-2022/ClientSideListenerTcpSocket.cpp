#include "ClientSideListenerTcpSocket.h"


unsigned char* ClientSideListenerTcpSocket::stringToUnsignedCharArray(std::string str)
{
	const char* signedChars = str.c_str();
	unsigned char* unsignedChars = reinterpret_cast<unsigned char*>(const_cast<char*>(signedChars));
	return unsignedChars;
}

ClientSideListenerTcpSocket::ClientSideListenerTcpSocket(char* listeningAddress, int listeningPort, std::shared_ptr<spdlog::logger> logger, std::shared_ptr<CryptoProvider> cryptoProvider)
{
	this->logger = logger;
	this->listeningPort = listeningPort;
	this->listeningAddress = listeningAddress;
	this->cryptoProvider = cryptoProvider;
	if (cryptoProvider == nullptr)
	{
		this->logger->info("Starting listening on {}:{} in Socks5 mode...", this->listeningAddress, this->listeningPort);
		//this->clientHandler = &ClientSideListenerTcpSocket::socksFiveClientHandler;
	}
	else
	{
		this->logger->info("Starting listening on {}:{} in ShadowSocks mode...", this->listeningAddress, this->listeningPort);
		//this->clientHandler = &ClientSideListenerTcpSocket::shadowSocksClientHandler;
	}
}

ClientSideListenerTcpSocket::~ClientSideListenerTcpSocket()
{
	closeListener();
}

//void ClientSideListenerSocket::clientHandler(SOCKET* acceptedConnection)
//{
	//[encrypted payload length][length tag][encrypted payload][payload tag]
	// 0 - [salt] = 32
	// 1 - [encrypted payload length][length tag] = [2][16]
	// 2 - [encrypted payload][payload tag] = [n][16]
//}

/*
boost::asio::awaitable<void> ClientSideListenerTcpSocket::socksFiveClientHandler(boost::asio::ip::tcp::socket clientConnectionFromSocket)
{
	//std::shared_ptr<RemoteConnection> remoteConnection = std::make_shared<TcpRemoteConnection>(new TcpRemoteConnection(this->logger));
	//std::shared_ptr<ClientConnection> clientConnection = std::make_shared<TcpClientConnection>(new TcpClientConnection(clientConnectionFromSocket, this->logger));

	//SocksFiveSession* session = new SocksFiveSession(clientConnection, remoteConnection, this->logger);
	//session->startProxySession();
	co_await std::cout;
	return;
}
*/

boost::asio::awaitable<void> ClientSideListenerTcpSocket::shadowSocksClientHandler(boost::asio::ip::tcp::socket* clientConnectionFromSocket)
{
	try
	{
		this->logger->info("shadowSocksClientHandler");
		
		std::shared_ptr<RemoteConnection> remoteConnection(new TcpRemoteConnection(this->logger));
		std::shared_ptr<ClientConnection> clientConnection(new TcpClientConnection(clientConnectionFromSocket, this->logger));
		try
		{
			std::string keyStr = "1111";

			char* key = new char[keyStr.length() + 1];
			strcpy(key, keyStr.c_str());
			byte* keyB = reinterpret_cast<byte*>(key);

			std::shared_ptr<CryptoProvider> localCP(new ShadowSocksChaCha20Poly1305(keyB, keyStr.length(), this->logger));
			try
			{
				this->logger->critical("Exception caught during session... 0");

				if (this->logger != NULL)
				{
					std::cout << 1 << std::endl;
				}
				else
				{
					std::cout << 0 << std::endl;
				}

				std::shared_ptr<SocksFiveSession> session(new ShadowSocksSession(clientConnection, remoteConnection, localCP, this->logger));
			}
			catch (Exception e)
			{
				this->logger->critical("Exception caught during session... 1");
			}

		}
		catch (Exception e)
		{
			this->logger->critical("Exception caught during session... 2");
		}

	}
	catch (Exception e)
	{
		this->logger->critical("Exception caught during session... 3");
	}
	
}

int ClientSideListenerTcpSocket::startListener()
{
	this->logger->info("startListener");
	boost::asio::io_context ioContext;
    boost::asio::co_spawn(ioContext, handleConnections(), boost::asio::detached);
	//boost::asio::co_spawn(ioContext, handleConnections(), boost::asio::use_awaitable);
	ioContext.run();
	this->logger->info("startListener-end");
}


boost::asio::awaitable<void> ClientSideListenerTcpSocket::handleConnections()
{
	try
	{
		this->logger->info("handleConnections");
		const auto executor = co_await boost::asio::this_coro::executor;
		this->logger->info("handleConnections-1");
		boost::asio::ip::tcp::acceptor acceptor(executor, { boost::asio::ip::tcp::v4(), 2222 });
		this->logger->info("handleConnections-2");
		while (true)
		{
			this->logger->info("handleConnections-while");
			//boost::asio::ip::tcp::socket acceptedConnection = new boost::asio::ip::tcp::socket;
			boost::asio::ip::tcp::socket acceptedConnection = co_await acceptor.async_accept(boost::asio::use_awaitable);
			boost::asio::co_spawn(executor, shadowSocksClientHandler(&acceptedConnection), boost::asio::detached);
		}
		this->logger->info("handleConnections-after-while");
	}
	catch (Exception e)
	{
		this->logger->critical("Exception while handling connection...");
	}
}






int ClientSideListenerTcpSocket::closeListener()
{
	//closesocket(sListener);
	//WSACleanup();
	this->logger->info("Listener on {}:{} closed...", this->listeningAddress, this->listeningPort);
	return 0;
}