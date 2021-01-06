#pragma once

#include "PipeMsg.h"
extern"C"
{
#include "utils/rc4.h"
}
#include "snappy.h"

class Cypher
{
public:

	Cypher(EncryMethod  method, const char* key, uint32_t keyLen);

	virtual ~Cypher();

	char* encode(char* data, uint32_t len, uint32_t& outLen);

	char* decode(EncryMethod  method, char* data, uint32_t len, uint32_t& outLen);

	EncryMethod getMethod();

protected:

	void resizeBuf(uint32_t len);

private:
	char* m_key;
	uint32_t  m_keyLen;
	EncryMethod m_method;

	char* m_cacheBuf;
	uint32_t m_cacheLen;
	struct rc4_state m_state;
};
