#pragma once

#include "net_uv/net_uv.h"

class VPNConfig
{
public:
	
	VPNConfig();

	bool initWithFile(const std::string& configFile);
	
	bool initWithContent(const std::string& config);

	bool isInit();
	
	int32_t getInt32(const char* key, int32_t defaultValue = 0);

	std::string getString(const char* key, const std::string& defaultValue = "");

protected:
	rapidjson::Document m_document;
	bool m_isInit;
};

static const char* g_vpnConfigFile = "config.json";
static const char* g_vpnDefaultConfig = "{"
"\"client_listenIP\": \"0.0.0.0\","
"\"remoteIP\" : \"47.75.218.200\","
"\"svr_listenIP\" : \"0.0.0.0\","
"\"client_listenPort\" : 8527,"
"\"svr_listenPort\" : 1002"
"}";
