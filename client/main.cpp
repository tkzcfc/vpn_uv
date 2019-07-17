#include "VPNClient.h"
#include "VPNConfig.h"
#include <iostream>

void ready_call(bool isReady)
{
	if (isReady)
	{
		printf("���ӳɹ�...\n");
	}
	else
	{
		printf("�Ͽ�����...\n");
	}
}

void main()
{
	net_uv::net_setLogLevel(NET_UV_L_INFO);

	VPNConfig cfg;
	if (!cfg.initWithFile(g_vpnConfigFile))
	{
		printf("�����ļ�'%s'������,ʹ��Ĭ������\n\n%s\n\n\n", g_vpnConfigFile, g_vpnDefaultConfig);
		cfg.initWithContent(g_vpnDefaultConfig);
	}

	if (cfg.isInit())
	{
		net_uv::DNSCache::getInstance()->setEnable(false);

		std::string client_listenIP = cfg.getString("client_listenIP");
		std::string remoteIP = cfg.getString("remoteIP");
		std::string svr_listenIP = cfg.getString("svr_listenIP");
		int32_t client_listenPort = cfg.getInt32("client_listenPort");
		int32_t svr_listenPort = cfg.getInt32("svr_listenPort");

		VPNClient* client = new VPNClient();
		
		if (!client->start(client_listenIP.c_str(), client_listenPort, remoteIP.c_str(), svr_listenPort, ready_call))
		{
			printf("start fail...\n");
			system("pause");
			return;
		}

		printf("�������ӷ�����...\n");
		while (true)
		{
			client->updateFrame();
			Sleep(1);
		}
		delete client;
	}
	else
	{
		printf("��ȡ����ʧ��\n");
	}
	system("pause");
}

