#pragma once

#include "Socks5Msg.h"
#include "utils/endian.h"

#define MSG_MAX_SIZE (1 << 18) // 256k
#define BLOCK_DATA_SIZE 1400

#define RECV_BUFFER_BLOCK_SIZE (1 << 14) // 16k

enum S2C_RESPONSE_CODE : uint8_t
{
	TCP_FAIL,
	TCP_SUC,
	TCP_TIME_OUT,
	UDP_FAIL,
	UDP_SUC,

	CODE_NONE
};


// 管道消息类型
enum PIPEMSG_TYPE : uint8_t
{
	INVALID = 0,

    // +---------+-----+------+----------+----------+
    // | MSGTYPE | CMD | ATYP | DST.ADDR | DST.PORT |
    // +---------+-----+------+----------+----------+
    // |   1     |  1  |  1   | Variable |    2     |
    // +---------+-----+------+----------+----------+
	C2S_REQUEST,

	// +---------+------+
	// | MSGTYPE | CODE |
	// +---------+------+
	// |   1     |  1   |
	// +---------+------+
	S2C_RESPONSE,

	// LEN = size(MSG)
    // +---------+--------+------+------+
    // | MSGTYPE | METHOD | LEN  | DATA |
    // +---------+--------+------+-------
    // |   1     |   1    |  4   |      |
    // +---------+--------+------+------+
	SEND_TCP_DATA,

	// LEN = size(MSG)
	// +---------+--------+------+------+----------+----------+----------+
	// | MSGTYPE | METHOD | LEN  | ATYP | DST.ADDR | DST.PORT |   DATA   |
	// +---------+--------+------+------+----------+----------+----------+
	// |   1     |   1    |  4   |  1   | Variable |    2     | Variable |
	// +---------+--------+------+------+----------+----------+----------+
	C2S_UDP_DATA,

	// LEN = size(MSG)
	// +---------+--------+------+------+----------+----------+----------+
	// | MSGTYPE | METHOD | LEN  | ATYP | SRC.ADDR | SRC.PORT |   DATA   |
	// +---------+--------+------+------+----------+----------+----------+
	// |   1     |   1    |  4   |  1   | Variable |    2     | Variable |
	// +---------+--------+------+------+----------+----------+----------+
	S2C_UDP_DATA,

	// +---------+
	// | MSGTYPE |
	// +---------+
	// |   1     |
	// +---------+
	S2C_DISCONNECT,

	// +---------+
	// | MSGTYPE |
	// +---------+
	// |   1     |
	// +---------+
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



struct S5AddrInfo
{
	uint8_t ATYP;
	uint16_t PORT;
	char ADDR[256];
};

struct PipeMsg {
    enum PIPEMSG_TYPE type;
    union {
    	struct {
			uint8_t CMD;
			S5AddrInfo ADDR;
    	}c2s_request;
        
		struct {
			S2C_RESPONSE_CODE CODE;
    	}s2c_response;

		struct {
			uint32_t LEN; // size(DATA)
			uint8_t METHOD;
			uint8_t* DATA;
    	}common_tcp_data;
		
		struct {
			uint32_t LEN; // size(DATA)
			uint8_t METHOD;
			uint8_t* DATA;
			S5AddrInfo ADDR;
    	}common_udp_data;
    };
};



class MsgHelper
{
public:

	static bool checkClientMsg(uint8_t *buf);

	static bool checkServerMsg(uint8_t *buf);
	
	static int32_t serializeMsg(const PipeMsg *msg, uint8_t *buf);

	static int32_t deserializeMsg(const uint8_t* buf, uint32_t len, PipeMsg* msg);

	static void destroyMsg(PipeMsg* msg);

	static void initMsg(PipeMsg* msg, PIPEMSG_TYPE type);

	static void printMsg(PipeMsg* msg);

	// ADDR
	static int32_t serializeAddr(const S5AddrInfo* info, uint8_t* buf);

	static int32_t resolvAddr(S5AddrInfo* info, uint8_t* data);
};


enum RUN_STATUS
{
	STOP,
	RUN,
	STOP_ING
};
