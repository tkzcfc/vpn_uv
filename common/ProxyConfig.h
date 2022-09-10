#pragma once

#include "net_uv.h"
#include "rapidjson/reader.h"
#include "rapidjson/document.h"

class ProxyConfig
{
public:
	
	ProxyConfig();
	
	static ProxyConfig* getInstance();

	bool initWithArgs(int argc, char** argv);

	bool isInit();
	
	int32_t getInt32(const char* key, int32_t defaultValue = 0);

	uint32_t getUInt32(const char* key, uint32_t defaultValue = 0);

	std::string getString(const char* key, const std::string& defaultValue = "");
	
	bool getBool(const char* key, bool defaultValue = false);

private:

	bool initWithFile(const std::string& configFile);

	bool initWithContent(const std::string& config);

protected:
	rapidjson::Document m_document;
	bool m_isInit;
	
	static ProxyConfig* instance;
};

static const char* g_vpnDefaultConfig = "{"
"\"client_listenIP\": \"0.0.0.0\","
"\"svr_listenIP\" : \"0.0.0.0\","
"\"remoteIP\" : \"47.75.218.200\","
"\"client_listenPort\" : 8527,"
"\"svr_listenPort\" : 1002,"
"\"use_kcp\" : false,"
"\"is_ipv6\" : false,"
"\"encry_method\" : \"RC4\","
"\"encry_key\" : \"key_abc\","
"\"client_listenCount\" : 65535,"
"\"svr_listenCount\" : 65535"
"}";

