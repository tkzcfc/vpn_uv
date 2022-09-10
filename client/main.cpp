#include "ProxyClient.h"
#include "ProxyConfig.h"

int main(int argc, char** argv)
{
	if (!ProxyConfig::getInstance()->initWithArgs(argc, argv))
		return -1;

	net_uv::net_setLogLevel(NET_UV_L_INFO);
	net_uv::DNSCache::getInstance()->setEnable(true);
	{
		ProxyClient client;
		
		if (!client.start())
		{
			printf("start fail...\n");
		}
	}
	printMemInfo();
	return 0;
}

