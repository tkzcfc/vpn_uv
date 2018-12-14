#include "VPNServer.h"
#include <iostream>

void main()
{
	net_uv::DNSCache::getInstance()->setEnable(true);
	VPNServer* s = new VPNServer();
	if (!s->start("0.0.0.0", 1002))
	{
		printf("start fail...\n");
		system("pause");
		return;
	}
	while (true)
	{
		s->updateFrame();
		Sleep(1);
	}
	delete s;
	system("pause");
}




