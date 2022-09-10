#pragma once

#include "PipeMsg.h"
#include <cstring>
extern"C"
{
#include "utils/rc4.h"
}
#include "snappy.h"

class Cypher
{
public:

	Cypher(EncryMethod  method, const char* key, size_t keyLen);

	virtual ~Cypher();

	char* encode(char* data, size_t len, size_t& outLen);

	char* decode(EncryMethod  method, char* data, size_t len, size_t& outLen);

	EncryMethod getMethod();

protected:

	void resizeBuf(size_t len);

private:
	char* m_key;
	size_t  m_keyLen;
	EncryMethod m_method;

	char* m_cacheBuf;
	size_t m_cacheLen;
	struct rc4_state m_state;
};
