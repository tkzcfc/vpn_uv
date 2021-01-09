#include "ProxyClient.h"
#include <iostream>

void main()
{
	net_uv::net_setLogLevel(NET_UV_L_INFO);
	net_uv::DNSCache::getInstance()->setEnable(true);

	ProxyClient* client = new ProxyClient();
	
	if (!client->start())
	{
		printf("start fail...\n");
	}
	delete client;

	printMemInfo();
	system("pause");
}

