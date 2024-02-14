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
		this->clientHandler = &ClientSideListenerTcpSocket::socksFiveClientHandler;
	}
	else
	{
		this->logger->info("Starting listening on {}:{} in ShadowSocks mode...", this->listeningAddress, this->listeningPort);
		this->clientHandler = &ClientSideListenerTcpSocket::shadowSocksClientHandler;
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

void ClientSideListenerTcpSocket::socksFiveClientHandler(std::shared_ptr<SOCKET> clientConnectionFromSocket)
{
	//std::shared_ptr<RemoteConnection> remoteConnection = std::make_shared<TcpRemoteConnection>(new TcpRemoteConnection(this->logger));
	//std::shared_ptr<ClientConnection> clientConnection = std::make_shared<TcpClientConnection>(new TcpClientConnection(clientConnectionFromSocket, this->logger));

	//SocksFiveSession* session = new SocksFiveSession(clientConnection, remoteConnection, this->logger);
	//session->startProxySession();

}

void ClientSideListenerTcpSocket::shadowSocksClientHandler(std::shared_ptr<SOCKET> clientConnectionFromSocket)
{
	std::shared_ptr<RemoteConnection> remoteConnection(new TcpRemoteConnection(this->logger));
	std::shared_ptr<ClientConnection> clientConnection(new TcpClientConnection(clientConnectionFromSocket, this->logger));


	std::string keyStr = "1111";

	char* key = new char[keyStr.length() + 1];
	strcpy(key, keyStr.c_str());
	byte* keyB = reinterpret_cast<byte*>(key);

	std::shared_ptr<CryptoProvider> localCP(new ShadowSocksChaCha20Poly1305(keyB, keyStr.length(), this->logger));

	try
	{
		std::shared_ptr<SocksFiveSession> session(new ShadowSocksSession(clientConnection, remoteConnection, localCP, this->logger));
	}
	catch (std::exception e)
	{
		this->logger->critical("Exception caught...");
	}
	


	
	//session->startProxySession();
}

int ClientSideListenerTcpSocket::startListener()
{
	if (WSAStartup(DLLVersion, &wsaData) != 0)
	{
		this->logger->critical("WSA initialization error...");
		exit(1);
	}
	addr.sin_addr.s_addr = inet_addr(listeningAddress);
	addr.sin_port = htons(listeningPort);
	addr.sin_family = AF_INET;
	sListener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sizeofaddr = sizeof(addr);
	if (sListener == SOCKET_ERROR)
	{
		this->logger->critical("Socket initialization error...");
		exit(1);
	}
	if (bind(sListener, (SOCKADDR*)&addr, sizeofaddr) == SOCKET_ERROR)
	{
		this->logger->critical("Binding socket error...");
		exit(1);
	}
	//int mss = 512;
	//setsockopt(sListener, IPPROTO_TCP, TCP_MAXSEG, (char*)&mss, sizeof(mss));
	if (listen(sListener, SOMAXCONN) == SOCKET_ERROR)
	{
		this->logger->critical("Listening start error...");
		exit(1);
	}
	this->logger->info("Listening started on {}:{}", this->listeningAddress, this->listeningPort);
	handleConnections();
}


void ClientSideListenerTcpSocket::handleConnections()
{
	while (true)
	{
		//SOCKET* acceptedConnection = new SOCKET;
		std::shared_ptr<SOCKET> acceptedConnection(new SOCKET());
		SOCKADDR_IN addr_c;
		int addrlen = sizeof(addr_c);

		if ((*acceptedConnection = accept(sListener, (struct sockaddr*)&addr_c, &addrlen)) != 0) {
			this->logger->info("Client connected from {}.{}.{}.{}:{}", 
				(unsigned char)addr_c.sin_addr.S_un.S_un_b.s_b1,
				(unsigned char)addr_c.sin_addr.S_un.S_un_b.s_b2,
				(unsigned char)addr_c.sin_addr.S_un.S_un_b.s_b3,
				(unsigned char)addr_c.sin_addr.S_un.S_un_b.s_b4,
				ntohs(addr_c.sin_port));


			std::thread clientHandlerThread(ClientSideListenerTcpSocket::clientHandler, this, acceptedConnection);
			//std::async(std::launch::async, ClientSideListenerTcpSocket::clientHandler, this, acceptedConnection);
			clientHandlerThread.detach();
			//Sleep(10);
		}
		else
		{
			this->logger->info("Connection failed");
		}
		//Sleep(10);
	}
}






int ClientSideListenerTcpSocket::closeListener()
{
	closesocket(sListener);
	WSACleanup();
	this->logger->info("Listener on {}:{} closed...", this->listeningAddress, this->listeningPort);
	return 0;
}