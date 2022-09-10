#include "Cypher.h"


Cypher::Cypher(EncryMethod  method, const char* key, size_t keyLen)
{
	m_method = method;
	m_cacheBuf = NULL;
	m_cacheLen = 0;

	if(keyLen == 0)
	{
		const char* defaultKey = "12@#";

		keyLen = strlen(defaultKey);

		m_key = (char*)malloc(keyLen);
		memcpy(m_key, defaultKey, keyLen);
		m_keyLen = keyLen;
	}
	else
	{
		m_key = (char*)malloc(keyLen);
		memcpy(m_key, key, keyLen);
		m_keyLen = keyLen;
	}
}

Cypher::~Cypher()
{
	free(m_key);
	if (m_cacheBuf)
		free(m_cacheBuf);
}

void Cypher::resizeBuf(size_t len)
{
	if (m_cacheLen < len)
	{
		if (m_cacheBuf)
			free(m_cacheBuf);
		m_cacheLen = len;
		m_cacheBuf = (char*)malloc(len);
	}
}

char* Cypher::encode(char* data, size_t len, size_t& outLen)
{
	outLen = 0;
	if(len == 0)
		return NULL;

	if (m_method == EncryMethod::SNAPPY)
	{
		resizeBuf(snappy::MaxCompressedLength(len));
		snappy::RawCompress(data, len, m_cacheBuf, &outLen);
		if (outLen == 0)
		{
			printf("snappy::Compress Error\n");
			return NULL;
		}
		return m_cacheBuf;
	}
	else if (m_method == EncryMethod::RC4)
	{
		resizeBuf(len);
		rc4_init(&m_state, (const u_char *)m_key, m_keyLen);
		rc4_crypt(&m_state, (const u_char*)data, (u_char*)m_cacheBuf, len);
		outLen = len;
		return m_cacheBuf;
	}
	else
	{
		outLen = len;
		return data;
	}
	return NULL;
}

char* Cypher::decode(EncryMethod method, char* data, size_t len, size_t& outLen)
{
	outLen = 0;

	if (len == 0)
		return NULL;

	if (method == EncryMethod::SNAPPY)
	{
		if (!snappy::GetUncompressedLength(data, len, &outLen))
		{
			outLen = 0;
			return NULL;
		}
		resizeBuf(outLen);

		if (!snappy::RawUncompress(data, len, m_cacheBuf))
		{
			printf("snappy::Uncompress error\n");
			outLen = 0;
			return NULL;
		}
		return m_cacheBuf;
	}
	else if (method == EncryMethod::RC4)
	{
		outLen = len;
		resizeBuf(outLen);
		rc4_init(&m_state, (const u_char *)m_key, m_keyLen);
		rc4_crypt(&m_state, (const u_char*)data, (u_char*)m_cacheBuf, len);
		return m_cacheBuf;
	}
	else if(method == EncryMethod::NONE)
	{
		outLen = len;
		return data;
	}

	return NULL;
}

EncryMethod Cypher::getMethod()
{
	return m_method;
}
