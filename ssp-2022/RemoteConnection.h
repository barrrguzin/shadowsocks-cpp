#pragma once

#include "Connection.h"
#include <iostream>
#include <thread>
#include <string>

class RemoteConnection : public Connection
{
public:
	int virtual initializeServerSideSocket(const char* targetAddress, int targetPort) = 0;
	int virtual startConnectionToServer() = 0;
};

