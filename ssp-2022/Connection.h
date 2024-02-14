#pragma once

class Connection
{
public:
	int virtual sendTo(char message[], int messageSize) = 0;
	int virtual recieveFrom(char message[], int messageSize) = 0;
	int virtual closeConnection() = 0;
};