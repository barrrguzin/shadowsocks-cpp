#include "TcpRemoteConnection.h"



TcpRemoteConnection::TcpRemoteConnection(std::shared_ptr<spdlog::logger> logger) 
{
	this->logger = logger;
}

TcpRemoteConnection::~TcpRemoteConnection()
{
	delete s;
	closeConnection();
}

int TcpRemoteConnection::initializeServerSideSocket(const char* targetAddress, int targetPort)
{
	TcpRemoteConnection::targetAddress = targetAddress;
	TcpRemoteConnection::targetPort = targetPort;

	boost::asio::io_service io_service;

	boost::asio::ip::tcp::resolver resolver(io_service);
	boost::asio::ip::tcp::resolver::query query(boost::asio::ip::tcp::v4(), targetAddress, std::to_string(targetPort));
	boost::asio::ip::tcp::resolver::iterator endpoints = resolver.resolve(query);
	boost::asio::ip::tcp::endpoint endpoint = endpoints->endpoint();

	boost::asio::ip::tcp::socket socket(io_service);
	socket.connect(endpoint);

	this->s = &socket;

	return 0;
}

int TcpRemoteConnection::startConnectionToServer()
{
	return 0;
}

boost::asio::awaitable<unsigned long long> TcpRemoteConnection::sendTo(char message[], int messageSize)
{
	return boost::asio::async_write(*s, boost::asio::buffer(message, messageSize), boost::asio::use_awaitable);
	//return boost::asio::write(*s, boost::asio::buffer(message, messageSize));
}

boost::asio::awaitable<unsigned long long> TcpRemoteConnection::recieveFrom(char message[], int messageSize)
{
	return boost::asio::async_read(*s, boost::asio::buffer(message, messageSize), boost::asio::use_awaitable);
	//return boost::asio::read(*s, boost::asio::buffer(message, messageSize));
}

int TcpRemoteConnection::closeConnection()
{
	closesocket(connection);
	WSACleanup();
	this->logger->debug("Server side socket closed: {}:{}", this->targetAddress, this->targetPort);
	return 0;
}