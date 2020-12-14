#pragma once

#include <stdint.h>
#include <string>

class Utils
{
public:
	static uint32_t swap_endian(uint32_t val);

	static uint32_t IPtoINT(char* szIp);

	struct NetAddr
	{
		uint8_t ATPE;
		uint16_t PORT;
		std::string ADDR;
	};
	static bool decodeNetAddr(char* data, uint32_t len, NetAddr& addr);

	static uint32_t getNetAddrLen(char* data, uint32_t len);
};