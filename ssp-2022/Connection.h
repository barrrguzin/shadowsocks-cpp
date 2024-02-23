#pragma once

#include <boost/asio.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/execution/executor.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/ip/tcp.hpp>

class Connection
{
public:
	boost::asio::awaitable<unsigned long long> virtual sendTo(char message[], int messageSize) = 0;
	boost::asio::awaitable<unsigned long long> virtual recieveFrom(char message[], int messageSize) = 0;
	int virtual closeConnection() = 0;
};