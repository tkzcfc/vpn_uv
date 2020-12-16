#pragma once

#include "Socks5Msg.h"

#define MSG_MAX_SIZE 65535*10
#define BLOCK_DATA_SIZE 1400


// 管道消息类型
enum PIPEMSG_TYPE
{
	C2S_REQUEST = 0xfefe,
	S2C_REQUEST,
	SEND_TCP_DATA,
	C2S_UDP_DATA,
	S2C_UDP_DATA,
	S2C_DISCONNECT,
	S2C_CANNOT_RESOLVE_ADDR,
};

// 加密方式
enum EncryMethod
{
	BEGIN,
	NONE,
	RC4,
	SNAPPY,
	END
};

struct MSG_P_Base
{
	PIPEMSG_TYPE msgType;
};

struct MSG_P_C2S_Request : public MSG_P_Base
{
	// 0x01 CONNECT
	// 0x02 BIND
	// 0x03 UDP
	uint8_t CMD;
	// 0x01 ipv4
	// 0x03 domain name
	// 0x04 ipv6
	uint8_t ATYP;
	uint16_t port;
	uint16_t len;
	// .ADDR
};
// 
struct MSG_P_S2C_Response : public MSG_P_Base
{
	// 0x00: tcp connect failed
	// 0x01: tcp connect succeeded
	// 0x02: tcp connect timed out
	// 0x03: udp ok
	// 0x04: udp fail
	uint8_t ret;
};

struct MSG_P_TCP_Data : public MSG_P_Base
{
	uint32_t len;
	uint16_t method;
	// .DATA
};

struct MSG_P_C2S_UDP_Data : MSG_P_TCP_Data
{
	// uint8_t FRAG;
	// uint8_t ATYP;
	// char[ATYP] .ADDR
	// uint16_t.PORT
	// .DATA
};

struct MSG_P_S2C_UDP_Data : MSG_P_TCP_Data
{
	// uint8_t ATYP;
	// char[ATYP] .ADDR
	// uint16_t.PORT
	// .DATA
};

enum RUN_STATUS
{
	STOP,
	RUN,
	STOP_ING
};
