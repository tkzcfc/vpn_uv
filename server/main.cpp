#include "VPNServer.h"
#include "VPNConfig.h"
#include <iostream>

void main()
{
	VPNConfig cfg;
	if (!cfg.initWithFile(g_vpnConfigFile))
	{
		printf("配置文件'%s'不存在,使用默认配置\n\n%s\n\n\n", g_vpnConfigFile, g_vpnDefaultConfig);
		cfg.initWithContent(g_vpnDefaultConfig);
	}

	if (cfg.isInit())
	{
		net_uv::DNSCache::getInstance()->setEnable(true);

		std::string client_listenIP = cfg.getString("client_listenIP");
		std::string remoteIP = cfg.getString("remoteIP");
		std::string svr_listenIP = cfg.getString("svr_listenIP");
		int32_t client_listenPort = cfg.getInt32("client_listenPort");
		int32_t svr_listenPort = cfg.getInt32("svr_listenPort");

		VPNServer* svr = new VPNServer();
		if (!svr->start(svr_listenIP.c_str(), svr_listenPort))
		{
			printf("start fail...\n");
			system("pause");
			return;
		}
		while (true)
		{
			svr->updateFrame();
			Sleep(1);
		}
		delete svr;
	}
	else
	{
		printf("读取配置失败\n");
	}
	system("pause");
}




