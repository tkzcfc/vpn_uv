#include "VPNConfig.h"


VPNConfig::VPNConfig()
{
	m_isInit = false;
}

bool VPNConfig::initWithFile(const std::string& configFile)
{
	if (m_isInit)
	{
		return false;
	}
	if (configFile.empty())
	{
		return false;
	}

	FILE* fp = fopen(configFile.c_str(), "rb");
	if (fp == NULL)
	{
		return false;
	}

	fseek(fp, 0, SEEK_END);
	uint32_t fileSize = ftell(fp);

	if (fileSize <= 0)
	{
		fclose(fp);
		return false;
	}

	char* buf = new char[fileSize + 1];
	fseek(fp, 0, SEEK_SET);
	fread(buf, fileSize, 1, fp);
	fclose(fp);

	buf[fileSize] = '\0';

	m_document.Parse(buf, fileSize);
	delete[] buf;

	if (m_document.HasParseError())
	{
		printf("json parse error: %u", m_document.GetParseError());
		return false;
	}
	m_isInit = true;
	return true;
}

bool VPNConfig::initWithContent(const std::string& config)
{
	if (m_isInit)
	{
		return false;
	}
	m_document.Parse(config.c_str(), config.size());

	if (m_document.HasParseError())
	{
		printf("json parse error: %u", m_document.GetParseError());
		return false;
	}
	m_isInit = true;
	return true;
}

bool VPNConfig::isInit()
{
	return m_isInit;
}

int32_t VPNConfig::getInt32(const char* key, int32_t defaultValue)
{
	if (m_document.HasMember(key))
	{
		rapidjson::Value& out_value = m_document[key];
		if (out_value.IsInt())
		{
			return out_value.GetInt();
		}
	}
	return defaultValue;
}

std::string VPNConfig::getString(const char* key, const std::string& defaultValue)
{
	if (m_document.HasMember(key))
	{
		rapidjson::Value& out_value = m_document[key];
		if (out_value.IsString())
		{
			return out_value.GetString();
		}
	}
	return defaultValue;
}
