#include "ProxyServer.h"
#include <iostream>

void main()
{
	net_uv::net_setLogLevel(NET_UV_L_INFO);
	net_uv::DNSCache::getInstance()->setEnable(true);

	ProxyServer* svr = new ProxyServer();
	if (!svr->start())
	{
		printf("start fail...\n");
	}
	delete svr;
	system("pause");
}




