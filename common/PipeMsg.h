#pragma once

#include "Socks5Msg.h"

enum PIPEMSG_TYPE
{
	C2S_REQUEST,
	S2C_REQUEST,
	C2S_SENDDATA,
	S2C_SENDDATA,
	C2S_DISCONNECT,
	S2C_DISCONNECT,
};

struct MSG_P_Base
{
	uint32_t sessionId;
	PIPEMSG_TYPE msgType;
};

struct MSG_P_C2S_Request : public MSG_P_Base
{
	MSG_P_C2S_Request(uint32_t inId)
	{
		sessionId = inId;
		msgType = PIPEMSG_TYPE::C2S_REQUEST;
	}
	char szIP[DOMAIN_NAME_MAX_LENG];
	uint8_t ATYP;
	uint16_t port;
};

struct MSG_P_S2C_Request : public MSG_P_Base
{
	MSG_P_S2C_Request(uint32_t inId)
	{
		sessionId = inId;
		msgType = PIPEMSG_TYPE::S2C_REQUEST;
	}
	uint8_t ret;
};