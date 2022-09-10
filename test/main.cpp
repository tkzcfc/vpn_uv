#include "PipeMsg.h"
#include <iostream>
#include "utils/endian.h"
#include "net_uv.h"

NS_NET_UV_OPEN;

char* ByteToHex(const unsigned char* vByte, const int vLen)
{
	if (!vByte)
	{
		return NULL;
	}

	char* tmp = new char[vLen * 2 + 1];

	int tmp2;
	for (int i = 0; i < vLen; i++)
	{
		tmp2 = (int)(vByte[i]) / 16;
		tmp[i * 2] = (char)(tmp2 + ((tmp2 > 9) ? 'A' - 10 : '0'));
		tmp2 = (int)(vByte[i]) % 16;
		tmp[i * 2 + 1] = (char)(tmp2 + ((tmp2 > 9) ? 'A' - 10 : '0'));
	}

	tmp[vLen * 2] = '\0';
	return tmp;
}

void printHex(const unsigned char* value, const int len)
{
	char* data = ByteToHex(value, len);
	int strl = strlen(data) / 2;
	char buf[3] = { 0 };
	for (int i = 0; i < strl; ++i)
	{
		buf[0] = data[i * 2];
		buf[1] = data[i * 2 + 1];
		printf("%s ", buf);
	}
	printf("\n");
	delete[]data;
}


void test_C2S_REQUEST()
{
	// +---------+-----+------+----------+----------+
	// | MSGTYPE | CMD | ATYP | DST.ADDR | DST.PORT |
	// +---------+-----+------+----------+----------+
	// |   1     |  1  |  1   | Variable |    2     |
	// +---------+-----+------+----------+----------+

	uint8_t *buf = new uint8_t[MSG_MAX_SIZE];
	PipeMsg msg;
	MsgHelper::initMsg(&msg, PIPEMSG_TYPE::C2S_REQUEST);
	msg.c2s_request.CMD = SOKS5_CMD_CONNECT;
	
	// SOKS5_ATYP_IPV4
	// SOKS5_ATYP_DOMAIN
	// SOKS5_ATYP_IPV6
	msg.c2s_request.ADDR.PORT = 35841;
	msg.c2s_request.ADDR.ATYP = SOKS5_ATYP_DOMAIN;
	
	if(msg.c2s_request.ADDR.ATYP == SOKS5_ATYP_IPV4)
	{
		strcpy(msg.c2s_request.ADDR.ADDR, "47.75.218.200");
	}
	else if(msg.c2s_request.ADDR.ATYP == SOKS5_ATYP_IPV6)
	{
		// fe80:0000:0000:0000:0000:0000:0001:0000  fe80::0001:0000
		strcpy(msg.c2s_request.ADDR.ADDR, "fe80::0001:0000");
	}
	else if(msg.c2s_request.ADDR.ATYP == SOKS5_ATYP_DOMAIN)
	{
		strcpy(msg.c2s_request.ADDR.ADDR, "www.baidu.com");
	}

	uint32_t len = MsgHelper::serializeMsg(&msg, buf);

	printHex(buf, len);

	PipeMsg newmsg;
	uint32_t newlen = MsgHelper::deserializeMsg(buf, MSG_MAX_SIZE, &newmsg);

	printf("len = %d, newlen = %d\n", len, newlen);
	assert(newlen == len);
	
	MsgHelper::printMsg(&msg);
	MsgHelper::printMsg(&newmsg);	
	MsgHelper::destroyMsg(&msg);
	MsgHelper::destroyMsg(&newmsg);
	

	delete[]buf;
}

void test_C2S_REQUEST_check()
{
	PipeMsg msg;
	MsgHelper::initMsg(&msg, PIPEMSG_TYPE::C2S_REQUEST);
	
	const uint8_t buf1[] = {
		0x01, 
		0x01, 
		0x03, 
		0x0D, 0x77, 0x77, 0x77, 0x2E, 0x62, 0x61, 0x69, 0x64, 0x75, 0x2E, 0x63, 0x6F, 0x6D, 
		0x8C, 0x01};
	assert(MsgHelper::deserializeMsg(buf1, sizeof(buf1), &msg) == 19);
	MsgHelper::destroyMsg(&msg);
	
	
	const uint8_t buf2[] = {
		0x01, 
		0x01, 
		0x03, 
		0x0E, 0x77, 0x77, 0x77, 0x2E, 0x62, 0x61, 0x69, 0x64, 0x75, 0x2E, 0x63, 0x6F, 0x6D, 
		0x8C, 0x01};
	assert(MsgHelper::deserializeMsg(buf2, sizeof(buf2), &msg) == 0);
	MsgHelper::destroyMsg(&msg);
	
	const uint8_t buf3[] = {
		0x01, 
		0x01, 
		0x03, 
		0x0C, 0x77, 0x77, 0x77, 0x2E, 0x62, 0x61, 0x69, 0x64, 0x75, 0x2E, 0x63, 0x6F, 0x6D, 
		0x8C, 0x01};
	assert(MsgHelper::deserializeMsg(buf3, sizeof(buf3), &msg) == 18);
	MsgHelper::destroyMsg(&msg);
	
	// error: domain len (0x00)
	const uint8_t buf4[] = {
		0x01, 
		0x01, 
		0x03, 
		0x00, 0x77, 0x77, 0x77, 0x2E, 0x62, 0x61, 0x69, 0x64, 0x75, 0x2E, 0x63, 0x6F, 0x6D, 
		0x8C, 0x01};
	assert(MsgHelper::deserializeMsg(buf4, sizeof(buf4), &msg) == -1);
	MsgHelper::destroyMsg(&msg);
	
	// error: cmd(0xdd) overflow
	const uint8_t buf5[] = {0x01, 0xdd,};
	assert(MsgHelper::deserializeMsg(buf5, sizeof(buf5), &msg) == -1);
	MsgHelper::destroyMsg(&msg);
	
	// error: atyp(0xdd) overflow
	const uint8_t buf6[] = {0x01,  0x01, 0xdd};
	assert(MsgHelper::deserializeMsg(buf6, sizeof(buf6), &msg) == -1);
	MsgHelper::destroyMsg(&msg);
	
	
	const uint8_t buf7[] = {0x01, 0x01, 0x01, 0x2F, 0x4B, 0xDA, 0xC8, 0xFF, 0xF1, 0xDD};
	assert(MsgHelper::deserializeMsg(buf7, sizeof(buf7), &msg) == 9);
	MsgHelper::destroyMsg(&msg);
}

void test_S2C_RESPONSE()
{
	uint8_t *buf = new uint8_t[MSG_MAX_SIZE];
	PipeMsg msg;
	MsgHelper::initMsg(&msg, PIPEMSG_TYPE::S2C_RESPONSE);
	msg.s2c_response.CODE = S2C_RESPONSE_CODE::TCP_TIME_OUT;
	
	uint32_t len = MsgHelper::serializeMsg(&msg, buf);
	printHex(buf, len);
	
	PipeMsg newmsg;
	uint32_t newlen = MsgHelper::deserializeMsg(buf, MSG_MAX_SIZE, &newmsg);

	printf("len = %d, newlen = %d\n", len, newlen);
	assert(newlen == len);
	
	
	MsgHelper::printMsg(&msg);
	MsgHelper::printMsg(&newmsg);	
	MsgHelper::destroyMsg(&msg);
	MsgHelper::destroyMsg(&newmsg);
	
	delete[]buf;
}

void test_S2C_RESPONSE_check()
{
	PipeMsg msg;
	MsgHelper::initMsg(&msg, PIPEMSG_TYPE::S2C_RESPONSE);
	
	const uint8_t buf1[] = {0x02};
	assert(MsgHelper::deserializeMsg(buf1, sizeof(buf1), &msg) == 0);
	MsgHelper::destroyMsg(&msg);
	
	// error: code(0x05) >= S2C_RESPONSE_CODE::CODE_NONE
	const uint8_t buf2[] = {0x02, 0x05};
	assert(MsgHelper::deserializeMsg(buf2, sizeof(buf2), &msg) == -1);
	MsgHelper::destroyMsg(&msg);
	
	const uint8_t buf3[] = {0x02, 0x02, 0x03};
	assert(MsgHelper::deserializeMsg(buf3, sizeof(buf3), &msg) == 2);
	MsgHelper::destroyMsg(&msg);
}


void test_SEND_TCP_DATA()
{
	// LEN = size(MSG)
    // +---------+--------+------+------+
    // | MSGTYPE | METHOD | LEN  | DATA |
    // +---------+--------+------+-------
    // |   1     |   1    |  4   |      |
    // +---------+--------+------+------+
	uint8_t *buf = new uint8_t[MSG_MAX_SIZE];
	PipeMsg msg;
	MsgHelper::initMsg(&msg, PIPEMSG_TYPE::SEND_TCP_DATA);
	msg.common_tcp_data.METHOD = 2;
	msg.common_tcp_data.LEN = 5;
	msg.common_tcp_data.DATA = (uint8_t*)fc_malloc(msg.common_tcp_data.LEN);
	
	for(auto i = 0; i < msg.common_tcp_data.LEN; ++i)
		msg.common_tcp_data.DATA[i] = i + 1;
	
	uint32_t len = MsgHelper::serializeMsg(&msg, buf);
	printHex(buf, len);
	
	PipeMsg newmsg;
	uint32_t newlen = MsgHelper::deserializeMsg(buf, MSG_MAX_SIZE, &newmsg);

	printf("len = %d, newlen = %d\n", len, newlen);
	assert(newlen == len);
	
	assert(memcmp(msg.common_tcp_data.DATA, newmsg.common_tcp_data.DATA, msg.common_tcp_data.LEN) == 0);
	
	MsgHelper::printMsg(&msg);
	MsgHelper::printMsg(&newmsg);	
	MsgHelper::destroyMsg(&msg);
	MsgHelper::destroyMsg(&newmsg);
	
	delete[]buf;
}

void test_SEND_TCP_DATA_check()
{
	PipeMsg msg;
	MsgHelper::initMsg(&msg, PIPEMSG_TYPE::SEND_TCP_DATA);
	
	const uint8_t buf1[] = {0x03, 0x02, 0x00, 0x00, 0x00, 0x0A, 0x01, 0x02, 0x03, 0x04, 0x05};
	assert(MsgHelper::deserializeMsg(buf1, sizeof(buf1), &msg) == 10);
	MsgHelper::destroyMsg(&msg);
	
	// error: method(0x00)
	const uint8_t buf2[] = {0x03, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x01, 0x02, 0x03, 0x04, 0x05};
	assert(MsgHelper::deserializeMsg(buf2, sizeof(buf2), &msg) == -1);
	MsgHelper::destroyMsg(&msg);
	
	// error: len(0x06) < min
	const uint8_t buf3[] = {0x03, 0x02, 0x00, 0x00, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05};
	assert(MsgHelper::deserializeMsg(buf3, sizeof(buf3), &msg) == -1);
	MsgHelper::destroyMsg(&msg);
	
	const uint8_t buf4[] = {0x03, 0x02, 0x03, 0x03, 0x03};
	assert(MsgHelper::deserializeMsg(buf4, sizeof(buf4), &msg) == 0);
	MsgHelper::destroyMsg(&msg);
	
	// error: len(0x03131233) overflow
	const uint8_t buf5[] = {0x03, 0x02, 0x03, 0x13, 0x23, 0x33};
	assert(MsgHelper::deserializeMsg(buf5, sizeof(buf5), &msg) == -1);
	MsgHelper::destroyMsg(&msg);
}



void test_C2S_UDP_DATA()
{
	// LEN = size(MSG)
	// +---------+--------+------+------+----------+----------+----------+
	// | MSGTYPE | METHOD | LEN  | ATYP | DST.ADDR | DST.PORT |   DATA   |
	// +---------+--------+------+------+----------+----------+----------+
	// |   1     |   1    |  4   |  1   | Variable |    2     | Variable |
	// +---------+--------+------+------+----------+----------+----------+
	uint8_t *buf = new uint8_t[MSG_MAX_SIZE];
	PipeMsg msg;
	MsgHelper::initMsg(&msg, PIPEMSG_TYPE::C2S_UDP_DATA);
	msg.common_udp_data.METHOD = 2;
	msg.common_udp_data.LEN = 5;
	msg.common_udp_data.DATA = (uint8_t*)fc_malloc(msg.common_tcp_data.LEN);
	
	// SOKS5_ATYP_IPV4
	// SOKS5_ATYP_DOMAIN
	// SOKS5_ATYP_IPV6
	msg.common_udp_data.ADDR.PORT = 65535;
	msg.common_udp_data.ADDR.ATYP = SOKS5_ATYP_DOMAIN;
	
	if(msg.common_udp_data.ADDR.ATYP == SOKS5_ATYP_IPV4)
	{
		strcpy(msg.common_udp_data.ADDR.ADDR, "47.75.218.200");
	}
	else if(msg.common_udp_data.ADDR.ATYP == SOKS5_ATYP_IPV6)
	{
		// fe80:0000:0000:0000:0000:0000:0001:0000  fe80::0001:0000
		strcpy(msg.common_udp_data.ADDR.ADDR, "fe80::0001:0000");
	}
	else if(msg.common_udp_data.ADDR.ATYP == SOKS5_ATYP_DOMAIN)
	{
		strcpy(msg.common_udp_data.ADDR.ADDR, "www.baidu.com");
	}
	
	for(auto i = 0; i < msg.common_udp_data.LEN; ++i)
		msg.common_udp_data.DATA[i] = i + 1;
	
	uint32_t len = MsgHelper::serializeMsg(&msg, buf);
	printHex(buf, len);
	
	PipeMsg newmsg;
	uint32_t newlen = MsgHelper::deserializeMsg(buf, MSG_MAX_SIZE, &newmsg);

	printf("len = %d, newlen = %d\n", len, newlen);
	assert(newlen == len);
	
	assert(memcmp(msg.common_udp_data.DATA, newmsg.common_udp_data.DATA, msg.common_udp_data.LEN) == 0);
	
	MsgHelper::printMsg(&msg);
	MsgHelper::printMsg(&newmsg);	
	MsgHelper::destroyMsg(&msg);
	MsgHelper::destroyMsg(&newmsg);
	
	delete[]buf;
}

void test_C2S_UDP_DATA_check()
{
	PipeMsg msg;
	MsgHelper::initMsg(&msg, PIPEMSG_TYPE::C2S_UDP_DATA);
	
	// error: len(0x0d) < min
	const uint8_t buf1[] = {0x04, 0x02, 0x00, 0x00, 0x00, 0x0D, 0x04, 0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0xFF, 0xFF, 0x01, 0x02, 0x03, 0x04, 0x05};
	assert(MsgHelper::deserializeMsg(buf1, sizeof(buf1), &msg) == -1);
	MsgHelper::destroyMsg(&msg);
	
	// error: len(0x01020301) overflow
	const uint8_t buf2[] = {0x04, 0x02, 0x01, 0x02, 0x03, 0x04, 0x04, 0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0xFF, 0xFF, 0x01, 0x02, 0x03, 0x04, 0x05};
	assert(MsgHelper::deserializeMsg(buf2, sizeof(buf2), &msg) == -1);
	MsgHelper::destroyMsg(&msg);
	
	// error: domain len(0x00)
	const uint8_t buf3[] = {0x04, 0x02, 0x00, 0x00, 0x00, 0x1C, 0x03, 0x00, 0x77, 0x77, 0x77, 0x2E, 0x62, 0x61, 0x69, 0x64, 0x75, 0x2E, 0x63, 0x6F, 0x6D, 0xFF, 0xFF, 0x01, 0x02, 0x03, 0x04, 0x05};
	assert(MsgHelper::deserializeMsg(buf3, sizeof(buf3), &msg) == -1);
	MsgHelper::destroyMsg(&msg);
	
	const uint8_t buf4[] = {0x04, 0x02, 0x03, 0x03, 0x03};
	assert(MsgHelper::deserializeMsg(buf4, sizeof(buf4), &msg) == 0);
	MsgHelper::destroyMsg(&msg);
		
	const uint8_t buf5[] = {0x04, 0x02, 0x00, 0x00, 0x00, 0x1C, 0x03, 0x0D, 0x77, 0x77, 0x77, 0x2E, 0x62, 0x61, 0x69, 0x64, 0x75, 0x2E, 0x63, 0x6F, 0x6D, 0xFF, 0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0xEE};
	assert(MsgHelper::deserializeMsg(buf5, sizeof(buf5), &msg) == 28);
	assert(strcmp("www.baidu.com", msg.common_udp_data.ADDR.ADDR) == 0);
	assert(msg.common_udp_data.ADDR.PORT == 65535);
	
	MsgHelper::destroyMsg(&msg);
	
	// error: len(0x17) < min
	const uint8_t buf6[] = {0x04, 0x02, 0x00, 0x00, 0x00, 0x17, 0x03, 0x0D, 0x77, 0x77, 0x77, 0x2E, 0x62, 0x61, 0x69, 0x64, 0x75, 0x2E, 0x63, 0x6F, 0x6D, 0xFF, 0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0xEE};
	assert(MsgHelper::deserializeMsg(buf6, sizeof(buf6), &msg) == -1);
	MsgHelper::destroyMsg(&msg);
}


int main()
{
	printf("test_C2S_REQUEST ------------------------->\n");
	test_C2S_REQUEST();
	test_C2S_REQUEST_check();
	
	printf("\n\n\n");
	printf("test_S2C_RESPONSE ------------------------->\n");
	test_S2C_RESPONSE();
	test_S2C_RESPONSE_check();
	
	printf("\n\n\n");
	printf("test_SEND_TCP_DATA ------------------------->\n");
	test_SEND_TCP_DATA();
	test_SEND_TCP_DATA_check();
	
	printf("\n\n\n");
	printf("test_C2S_UDP_DATA ------------------------->\n");
	test_C2S_UDP_DATA();
	test_C2S_UDP_DATA_check();	
	
	printMemInfo();
	//system("pause");

	return 0;
}

