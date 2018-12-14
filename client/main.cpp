#include "VPNClient.h"
#include <iostream>

void ready_call(bool isReady)
{
	if (isReady)
	{
		printf("连接成功...\n");
	}
	else
	{
		printf("断开连接...\n");
	}
}

void main()
{
	net_uv::DNSCache::getInstance()->setEnable(false);
	VPNClient* c = new VPNClient();

	//const char* remoteIP = "39.105.20.204";
	const char* remoteIP = "113.10.244.202";
	//const char* remoteIP = "127.0.0.1";

	if (!c->start("127.0.0.1", 8527, remoteIP, 1002, ready_call))
	{
		printf("start fail...\n");
		system("pause");
		return;
	}
	printf("正在连接服务器...\n");
	while (true)
	{
		c->updateFrame();
		Sleep(1);
	}
	delete c;
	system("pause");
}

