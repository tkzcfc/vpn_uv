#pragma once

#include <stdint.h>
#include <string>

class Utils
{
public:
	struct NetAddr
	{
		uint8_t ATPE;
		uint16_t PORT;
		std::string ADDR;
	};
	/*
	* 获取地址信息
	*/
	static bool decodeNetAddr(char* data, uint32_t len, NetAddr& addr);

	/*
	* 获取地址信息长度

	+----------返回长度-----------+
	+------+----------+----------+

	| ATYP | DST.ADDR | DST.PORT |

	+------+----------+----------+

	|  1   | Variable |    2     |

	+------+----------+----------+
	*/
	static uint32_t getNetAddrLen(char* data, uint32_t len);
};