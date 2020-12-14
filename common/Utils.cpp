#include "Utils.h"
#include <string>
#include "net_uv.h"
#include "PipeMsg.h"

#define TWO_CHAR_TO_SHORT(A, I) A = (((uint8_t)data[I]) << 8) | ((uint8_t)data[(I + 1)])

uint32_t Utils::swap_endian(uint32_t val) 
{
	val = ((val << 8) & 0xFF00FF00) | ((val >> 8) & 0xFF00FF);
	return (val << 16) | (val >> 16);
}

uint32_t Utils::IPtoINT(char* szIp)
{
	uint32_t nRet = 0;
	if(szIp == NULL)
		return nRet;

    char* szBufTemp = NULL;
    char* szBuf = strtok_s(szIp,".",&szBufTemp);

    int i = 0;
    while(NULL != szBuf)
    {
        nRet += atoi(szBuf) << ((3-i)*8);
        szBuf = strtok_s(NULL,".",&szBufTemp);
        i++;
    }
    return nRet;
}

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
		
		//struct in_addr addrtmp;
		//memcpy(&addrtmp, &data[1], 4);
		//addr.ADDR = ::inet_ntoa(addrtmp);

		//sprintf((char*)szBuf, "%u.%u.%u.%u", (uint8_t)data[1], (uint8_t)data[2], (uint8_t)data[3], (uint8_t)data[4]);
		//addr.ADDR = szBuf;
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
