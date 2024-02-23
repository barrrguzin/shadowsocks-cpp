#pragma once

#include <boost/asio/io_context.hpp>
#include <boost/asio/execution/executor.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/ip/tcp.hpp>

class ProxySession
{
public:
	int virtual startProxySession() = 0;
};