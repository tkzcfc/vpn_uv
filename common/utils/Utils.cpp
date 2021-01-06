#include "Utils.h"
#include <string>
#include "net_uv.h"
#include "PipeMsg.h"

uint32_t Utils::getNetAddrLen(char* data, uint32_t len)
{
	if (len < 7)
		return 0U;
	uint8_t ATYP = (uint8_t)(data[0]);
	// assert( ATYP == ipv4 || ATYP == domain || ATYP == ipv6 )
	if (ATYP != SOKS5_ATYP_IPV4 && ATYP != SOKS5_ATYP_DOMAIN && ATYP != SOKS5_ATYP_IPV6)
		return 0U;

	// assert(len == 7)
	if (ATYP == SOKS5_ATYP_IPV4)
		return 7U;

	// assert(len == 19)
	if (ATYP == SOKS5_ATYP_IPV6)
		return 19U;

	if (ATYP == SOKS5_ATYP_DOMAIN)
		return 4 + (uint8_t)data[1];

	return 0U;
}

bool Utils::decodeNetAddr(char* data, uint32_t len, NetAddr& addr)
{
	if (len < 7)
		return false;

	uint8_t ATYP = (uint8_t)(data[0]);
	// assert( ATYP == ipv4 || ATYP == domain || ATYP == ipv6 )
	if (ATYP != SOKS5_ATYP_IPV4 && ATYP != SOKS5_ATYP_DOMAIN && ATYP != SOKS5_ATYP_IPV6)
		return false;

	// ATYP == ipv4 && len != 1+4+2
	// assert(len == 7)
	if (ATYP == SOKS5_ATYP_IPV4 && len != 7)
		return false;

	// ATYP == ipv6 && len != 1+16+2
	// assert(len == 19)
	if (ATYP == SOKS5_ATYP_IPV6 && len != 19)
		return false;

	// ATYP == domain && len != (1 + 1 + data[4] + 2)
	if (ATYP == SOKS5_ATYP_DOMAIN && len != 4 + (uint8_t)data[1])
		return false;

	// ipv4
	if (ATYP == SOKS5_ATYP_IPV4)
	{
		char szBuf[128] = { 0 };
		::inet_ntop(AF_INET, data + 1, szBuf, sizeof(szBuf));
		addr.ADDR = szBuf;
	}
	// domain name
	else if (ATYP == SOKS5_ATYP_DOMAIN)
	{
		char szBuf[256] = { 0 };
		uint8_t addrLen = (uint8_t)data[1];
		for (uint8_t i = 0; i < addrLen; ++i)
		{
			szBuf[i] = data[2 + i];
		}
		addr.ADDR = szBuf;
	}
	// ipv6
	else if (ATYP == SOKS5_ATYP_IPV6)
	{
		char szBuf[128] = { 0 };
		::inet_ntop(AF_INET6, data + 1, szBuf, sizeof(szBuf));
		addr.ADDR = szBuf;
	}
	addr.ATPE = ATYP;
	addr.PORT = ::htons(*((uint16_t*)&data[len - 2]));

	return true;
}
