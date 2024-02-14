#include "shadowsocks-2022-proxy.h"

int main(int argc, char* argv[])
{
	std::string ipStr = "127.0.0.1";
	int port = 2222;

	
	std::shared_ptr<spdlog::logger> logger = spdlog::stdout_color_mt("console");
	logger->set_level(spdlog::level::trace);


	char* ip = new char[ipStr.length() + 1];
	strcpy(ip, ipStr.c_str());

	std::string keyStr = "1111";
	char* key = new char[keyStr.length() + 1];
	strcpy(key, keyStr.c_str());
	byte* keyB = reinterpret_cast<byte*>(key);

	//byte* key, int sizeOfKey, byte* iv, int sizeOfIV
	

	std::shared_ptr<CryptoProvider> cP(new ShadowSocksChaCha20Poly1305(keyB, keyStr.length(), logger));
	
	ClientSideListenerSocket* proxyServer = new ClientSideListenerTcpSocket(ip, port, logger, cP);
	proxyServer->startListener();

	return 0;
}