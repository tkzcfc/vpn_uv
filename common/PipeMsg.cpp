#include "PipeMsg.h"
#include <assert.h>
#include "net_uv.h"

NS_NET_UV_OPEN;

#define WAITE_MSG 0
#define INVALID_MSG -1
#define SERIALIZE_FAIL 0

static inline bool check_method(uint8_t method)
{
	if(method > EncryMethod::BEGIN && method < EncryMethod::END)
		return true;
	return false;
}

static inline bool check_cmd(uint8_t CMD)
{
	if(CMD != SOKS5_CMD_CONNECT && CMD != SOKS5_CMD_BIND && CMD != SOKS5_CMD_UDP)
		return false;
	return true;
}

static inline bool check_atyp(uint8_t ATYP)
{
	if (ATYP != SOKS5_ATYP_IPV4 && ATYP != SOKS5_ATYP_DOMAIN && ATYP != SOKS5_ATYP_IPV6)
		return false;
	return true;
}


bool MsgHelper::checkClientMsg(uint8_t* buf)
{
	PIPEMSG_TYPE type = (PIPEMSG_TYPE)buf[0];
	return type == PIPEMSG_TYPE::S2C_RESPONSE ||
		type == PIPEMSG_TYPE::SEND_TCP_DATA ||
		type == PIPEMSG_TYPE::S2C_UDP_DATA ||
		type == PIPEMSG_TYPE::S2C_DISCONNECT ||
		type == PIPEMSG_TYPE::S2C_CANNOT_RESOLVE_ADDR;
}

bool MsgHelper::checkServerMsg(uint8_t* buf)
{
	PIPEMSG_TYPE type = (PIPEMSG_TYPE)buf[0];
	return type == PIPEMSG_TYPE::C2S_REQUEST ||
		type == PIPEMSG_TYPE::SEND_TCP_DATA ||
		type == PIPEMSG_TYPE::C2S_UDP_DATA;
}

int32_t MsgHelper::serializeMsg(const PipeMsg *msg, uint8_t *buf)
{
	buf[0] = msg->type;
	switch(msg->type)
	{
		case PIPEMSG_TYPE::C2S_REQUEST:
		{
			buf[1] = msg->c2s_request.CMD;

			auto len = serializeAddr(&msg->c2s_request.ADDR, buf + 2);
			if(len <= 0)
			{
				assert(0);
				return SERIALIZE_FAIL;
			}
			return 2 + len;
		}break;
		case PIPEMSG_TYPE::S2C_RESPONSE:
		{
			buf[1] = (uint8_t)msg->s2c_response.CODE;
			return 2;
		}break;
		case PIPEMSG_TYPE::SEND_TCP_DATA:
		{
			buf[1] = msg->common_tcp_data.METHOD;

			uint32_t dataLen = msg->common_tcp_data.LEN;
			uint32_t msgLen = dataLen + 6;

			writeUint32InBigEndian(&buf[2], msgLen);
			memcpy(&buf[6], msg->common_tcp_data.DATA, dataLen);

			return msgLen;

		}break;
		case PIPEMSG_TYPE::C2S_UDP_DATA:
		case PIPEMSG_TYPE::S2C_UDP_DATA:
		{
			buf[1] = msg->common_udp_data.METHOD;
			auto len = serializeAddr(&msg->common_udp_data.ADDR, buf + 6);
			if(len <= 0)
			{
				assert(0);
				return SERIALIZE_FAIL;
			}

			auto dataLen = msg->common_udp_data.LEN;
			uint32_t msgLen = 6 + len + dataLen;

			// DATA
			memcpy(&buf[6 + len], msg->common_udp_data.DATA, dataLen);
			// LEN
			writeUint32InBigEndian(&buf[2], msgLen);

			return msgLen;
		}break;
		case PIPEMSG_TYPE::S2C_DISCONNECT:
		{
			return 1;
		}break;
		case PIPEMSG_TYPE::S2C_CANNOT_RESOLVE_ADDR:
		{
			return 1;
		}break;
	}
	assert(0);
	return SERIALIZE_FAIL;
}

int32_t MsgHelper::deserializeMsg(const uint8_t* buf, uint32_t len, PipeMsg* msg)
{
	msg->type = (PIPEMSG_TYPE)buf[0];
	switch(msg->type)
	{
		case PIPEMSG_TYPE::C2S_REQUEST:
		{
			if (len < 2)
				return WAITE_MSG;

			if (false == check_cmd(buf[1]))
				return INVALID_MSG;

			if (len < 3)
				return WAITE_MSG;

			uint8_t ATYP = buf[2];
			if (false == check_atyp(ATYP))
				return INVALID_MSG;

			if (len < 9)
				return WAITE_MSG;

			uint8_t ADDR_LEN = 4;
			if (ATYP == SOKS5_ATYP_DOMAIN)
			{
				if (buf[3] <= 0)
					return INVALID_MSG;
				ADDR_LEN = buf[3] + 1;
			}
			else if (ATYP == SOKS5_ATYP_IPV6)
			{
				ADDR_LEN = 16;
			}

			int msgLen = 3 + ADDR_LEN + 2;
			if (len < msgLen)
				return WAITE_MSG;

			msg->c2s_request.CMD = buf[1];
			auto addrlen = resolvAddr(&msg->c2s_request.ADDR, (uint8_t*)&buf[2]);
			if(addrlen <= 0)
				return INVALID_MSG;

			if (addrlen + 2 == msgLen)
				return msgLen;

			return INVALID_MSG;
		}break;
		case PIPEMSG_TYPE::S2C_RESPONSE:
		{
			if (len >= 2)
			{
				if (buf[1] >= 0 && buf[1] < S2C_RESPONSE_CODE::CODE_NONE)
				{
					msg->s2c_response.CODE = (S2C_RESPONSE_CODE)buf[1];
					return 2;
				}
				return INVALID_MSG;
			}
			return WAITE_MSG;
		}break;
		case PIPEMSG_TYPE::SEND_TCP_DATA:
		{
			if (len < 2)
				return WAITE_MSG;

			if (check_method(buf[1]) == false)
				return INVALID_MSG;

			if (len < 6)
				return WAITE_MSG;

			uint32_t msgLen = (uint32_t)readUint32InBigEndian((void*)&buf[2]);
			if (msgLen <= 6 || msgLen > MSG_MAX_SIZE)
				return INVALID_MSG;

			if (len < msgLen)
				return WAITE_MSG;

			msg->common_tcp_data.METHOD = buf[1];

			auto dataLen = msgLen - 6;

			msg->common_tcp_data.LEN = dataLen;
			msg->common_tcp_data.DATA = (uint8_t*)fc_malloc(dataLen);
			memcpy(msg->common_tcp_data.DATA, buf + 6, dataLen);

			return msgLen;

		}break;
		case PIPEMSG_TYPE::C2S_UDP_DATA:
		case PIPEMSG_TYPE::S2C_UDP_DATA:
		{
			if (len < 2)
				return WAITE_MSG;

			if (check_method(buf[1]) == false)
				return INVALID_MSG;

			if (len < 7)
				return WAITE_MSG;

			uint32_t msgLen = (uint32_t)readUint32InBigEndian((void*)&buf[2]);
			if (msgLen <= 13 || msgLen > MSG_MAX_SIZE)
				return INVALID_MSG;

			uint8_t ATYP = buf[6];
			if (false == check_atyp(ATYP))
				return INVALID_MSG;

			if (len < 8)
				return WAITE_MSG;

			uint8_t ADDR_LEN = 4;
			if (ATYP == SOKS5_ATYP_DOMAIN)
			{
				if (buf[7] <= 0)
					return INVALID_MSG;
				ADDR_LEN = buf[7] + 1;
			}
			else if (ATYP == SOKS5_ATYP_IPV6)
			{
				ADDR_LEN = 16;
			}

			if (msgLen <= 9 + ADDR_LEN || msgLen > MSG_MAX_SIZE)
				return INVALID_MSG;

			if (len < msgLen)
				return WAITE_MSG;
			
			msg->common_udp_data.METHOD = buf[1];
				
			auto addrlen = resolvAddr(&msg->common_udp_data.ADDR, (uint8_t*)&buf[6]);
			if (addrlen <= 0 || addrlen != ADDR_LEN + 3)
				return INVALID_MSG;

			auto dataLen = msgLen - addrlen - 6;
			if (dataLen <= 0)
				return INVALID_MSG;

			msg->common_udp_data.LEN = dataLen;
			msg->common_udp_data.DATA = (uint8_t*)fc_malloc(dataLen);
			memcpy(msg->common_udp_data.DATA, buf + 6 + addrlen, dataLen);

			return msgLen;
		}break;
		case PIPEMSG_TYPE::S2C_DISCONNECT:
		{
			return 1;
		}break;
		case PIPEMSG_TYPE::S2C_CANNOT_RESOLVE_ADDR:
		{
			return 1;
		}break;
	}
	assert(0);
	return INVALID_MSG;
}

void MsgHelper::destroyMsg(PipeMsg* msg)
{
	switch(msg->type)
	{
		case PIPEMSG_TYPE::SEND_TCP_DATA:
		{
			fc_free(msg->common_tcp_data.DATA);
			msg->common_tcp_data.DATA = NULL;
		}break;
		case PIPEMSG_TYPE::C2S_UDP_DATA:
		case PIPEMSG_TYPE::S2C_UDP_DATA:
		{
			fc_free(msg->common_udp_data.DATA);
			msg->common_udp_data.DATA = NULL;		
		}break;
	}
}

void MsgHelper::initMsg(PipeMsg* msg, PIPEMSG_TYPE type)
{
	memset(msg, 0, sizeof(PipeMsg));
	msg->type = type;
}

void MsgHelper::printMsg(PipeMsg* msg)
{
	switch(msg->type)
	{
		case PIPEMSG_TYPE::C2S_REQUEST:
		{
			const auto& info = msg->c2s_request.ADDR;

			if(msg->c2s_request.CMD == SOKS5_CMD_CONNECT)
				printf("[C2S_REQUEST]: CONNECT %s:%d\n", info.ADDR, (int32_t)info.PORT);
			else if(msg->c2s_request.CMD == SOKS5_CMD_BIND)
				printf("[C2S_REQUEST]: BIND %s:%d\n", info.ADDR, (int32_t)info.PORT);
			else if(msg->c2s_request.CMD == SOKS5_CMD_UDP)
				printf("[C2S_REQUEST]: UDP %s:%d\n", info.ADDR, (int32_t)info.PORT);
			else
				assert(0);
		}break;
		case PIPEMSG_TYPE::S2C_RESPONSE:
		{
			printf("[S2C_RESPONSE]: CODE:%d\n", (uint8_t)msg->s2c_response.CODE);
		}break;
		case PIPEMSG_TYPE::SEND_TCP_DATA:
		{
			printf("[TCP_DATA]: METHOD %d DATA %d\n", msg->common_tcp_data.METHOD, msg->common_tcp_data.LEN);
		}break;
		case PIPEMSG_TYPE::C2S_UDP_DATA:
		case PIPEMSG_TYPE::S2C_UDP_DATA:
		{
			printf("[UDP_DATA]: %s:%d -> METHOD %d DATA %d\n", msg->common_udp_data.ADDR.ADDR, (int32_t)msg->common_udp_data.ADDR.PORT, msg->common_udp_data.METHOD, msg->common_udp_data.LEN);
		}break;
		case PIPEMSG_TYPE::S2C_DISCONNECT:
		{
			printf("[S2C_DISCONNECT]\n");
		}break;
		case PIPEMSG_TYPE::S2C_CANNOT_RESOLVE_ADDR:
		{
			printf("[S2C_CANNOT_RESOLVE_ADDR]\n");			
		}break;
	}
}

int32_t MsgHelper::serializeAddr(const S5AddrInfo* info, uint8_t* buf)
{
	int32_t ADDR_LEN;
	buf[0] = info->ATYP;
	if(info->ATYP == SOKS5_ATYP_IPV4)
	{
		ADDR_LEN = 4;
		if(0 == ::inet_pton(AF_INET, info->ADDR, &buf[1]))
			return 0;
	}
	else if(info->ATYP == SOKS5_ATYP_IPV6)
	{
		ADDR_LEN = 16;
		if(0 == ::inet_pton(AF_INET6, info->ADDR, &buf[1]))
			return 0;
	}
	else
	{
		buf[1] = (uint8_t)strlen(info->ADDR);
		memcpy(buf + 2, info->ADDR, buf[1]);
		ADDR_LEN = buf[1] + 1;
	}
	writeUint16InBigEndian((void*)&buf[1 + ADDR_LEN], info->PORT);
	return 1 + ADDR_LEN + 2;
}

int32_t MsgHelper::resolvAddr(S5AddrInfo* info, uint8_t* data)
{
	uint8_t ATYP = data[0];
	uint32_t ADDR_LEN = 0;

	memset(info->ADDR, 0, sizeof(info->ADDR));
	// ipv4
	if (ATYP == SOKS5_ATYP_IPV4)
	{
		ADDR_LEN = 4;
		if(NULL == ::inet_ntop(AF_INET, data + 1, info->ADDR, sizeof(info->ADDR)))
			return 0;
	}
	// domain name
	else if (ATYP == SOKS5_ATYP_DOMAIN)
	{
		uint8_t addrLen = (uint8_t)data[1];
		for (uint8_t i = 0; i < addrLen; ++i)
		{
			info->ADDR[i] = data[2 + i];
		}

		ADDR_LEN = addrLen;
		ADDR_LEN ++;
	}
	// ipv6
	else if (ATYP == SOKS5_ATYP_IPV6)
	{
		ADDR_LEN = 16;
		if(NULL == ::inet_ntop(AF_INET6, data + 1, info->ADDR, sizeof(info->ADDR)))
			return 0;
	}
	else
	{
		assert(0);
		return 0;
	}
	info->ATYP = ATYP;
	info->PORT = ::htons(*((uint16_t*)&data[ADDR_LEN + 1]));

	return ADDR_LEN + 1 + 2;
}
