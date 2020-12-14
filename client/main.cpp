#include "VPNClient.h"
#include <iostream>

void main()
{
	net_uv::net_setLogLevel(NET_UV_L_INFO);
	net_uv::DNSCache::getInstance()->setEnable(true);

	VPNClient* client = new VPNClient();
	
	if (!client->start())
	{
		printf("start fail...\n");
	}
	delete client;
	system("pause");
}

