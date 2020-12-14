#pragma once

#include <cstdint>
#include <string>

// 域名最大长度
#define DOMAIN_NAME_MAX_LENG 256

#define UNSIGNE_CHAR_MAX_VALUE 255

#define IPV4_LEN 4
#define IPV6_LEN 16



#define SOKS5_VERSION 0x05

#define SOKS5_CMD_CONNECT 0x01
#define SOKS5_CMD_BIND 0x02
#define SOKS5_CMD_UDP 0x03

#define SOKS5_ATYP_IPV4 0x01
#define SOKS5_ATYP_DOMAIN 0x03
#define SOKS5_ATYP_IPV6 0x04


///http://www.cnblogs.com/yinzhengjie/p/7357860.html

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//创建与SOCKS5服务器的TCP连接后客户端需要先发送请求来协商版本及认证方式，格式为（以字节为单位）：
//VER	NMETHODS	METHODS
//1	1	1 - 255
//
//
//VER是SOCKS版本，这里应该是0x05；
//NMETHODS是METHODS部分的长度；
//METHODS是客户端支持的认证方式列表，每个方法占1字节。当前的定义是：
//0x00 不需要认证
//0x01 GSSAPI
//0x02 用户名、密码认证
//0x03 - 0x7F由IANA分配（保留）
//0x80 - 0xFE为私人方法保留
//0xFF 无可接受的方法
struct S5Msg_C2S_Verification
{
	uint8_t VER;
	uint8_t NMETHODS;
	uint8_t METHODS[UNSIGNE_CHAR_MAX_VALUE];
};

//服务器从客户端提供的方法中选择一个并通过以下消息通知客户端（以字节为单位）：
//VER	METHOD
//1		1
//
//
//VER是SOCKS版本，这里应该是0x05；
//METHOD是服务端选中的方法。如果返回0xFF表示没有一个认证方法被选中，客户端需要关闭连接。
struct S5Msg_S2C_Verification
{
	uint8_t VER;
	uint8_t METHOD;
};



//////////////////////////////////////////////////////////请求消息//////////////////////////////////////////////////////////

//之后客户端和服务端根据选定的认证方式执行对应的认证。认证结束后客户端就可以发送请求信息。如果认证方法有特殊封装要求，请求必须按照方法所定义的方式进行封装。
//
//SOCKS5请求格式（以字节为单位）：
//
//VER	CMD	RSV	ATYP	DST.ADDR	DST.PORT
//1	1	0x00	1	动态	2
//
//
//VER是SOCKS版本，这里应该是0x05；
//CMD是SOCK的命令码
//0x01表示CONNECT请求
//0x02表示BIND请求
//0x03表示UDP转发
//RSV 0x00，保留
//ATYP DST.ADDR类型
//0x01 IPv4地址，DST.ADDR部分4字节长度
//0x03域名，DST ADDR部分第一个字节为域名长度，DST.ADDR剩余的内容为域名，没有\0结尾。
//0x04 IPv6地址，16个字节长度。
//DST.ADDR 目的地址
//DST.PORT 网络字节序表示的目的端口
struct S5Msg_C2S_Request
{
	// 0x05
	uint8_t VER;
	// 0x01 CONNECT
	// 0x02 BIND
	// 0x03 UDP
	uint8_t CMD;
	// 0x00
	uint8_t RSV;
	// 0x01 ipv4
	// 0x03 domain name
	// 0x04 ipv6
	uint8_t ATYP;
	int8_t	DST_ADDR[DOMAIN_NAME_MAX_LENG];
	uint16_t DST_PORT;
};

//服务器按以下格式回应客户端的请求（以字节为单位）：
//
//VER	REP	RSV	ATYP	BND.ADDR	BND.PORT
//1	1	0x00	1	动态	2
//
//
//VER是SOCKS版本，这里应该是0x05；
//REP应答字段
//0x00表示成功
//0x01普通SOCKS服务器连接失败
//0x02现有规则不允许连接
//0x03网络不可达
//0x04主机不可达
//0x05连接被拒
//0x06 TTL超时
//0x07不支持的命令
//0x08不支持的地址类型
//0x09 - 0xFF未定义
//RSV 0x00，保留
//ATYP BND.ADDR类型
//0x01 IPv4地址，DST.ADDR部分4字节长度
//0x03域名，DST.ADDR部分第一个字节为域名长度，DST.ADDR剩余的内容为域名，没有\0结尾。
//0x04 IPv6地址，16个字节长度。
//BND.ADDR 服务器绑定的地址
//BND.PORT 网络字节序表示的服务器绑定的端口
struct S5Msg_S2C_Response
{
	uint8_t VER;
	uint8_t REP;
	uint8_t RSV; // 0x00
	// 0x01 ipv4
	// 0x03 domain name
	// 0x04 ipv6
	uint8_t ATYP;
	int8_t BND_ADDR[DOMAIN_NAME_MAX_LENG];
	uint16_t BND_PORT;
};

//////////////////////////////////////////////////////////密码校验//////////////////////////////////////////////////////////

//SOCKS5 用户名密码认证方式
//在客户端、服务端协商使用用户名密码认证后，客户端发出用户名密码，格式为（以字节为单位）：
//
//鉴定协议版本	用户名长度	用户名	密码长度	密码
//1					1	     动态	  1	        动态
//
//
//鉴定协议版本目前为 0x01 。
struct S5Msg_C2S_Password
{
	uint8_t VER;//0x01
	uint8_t USER_NAME_LEN;
	int8_t USER_NAME[UNSIGNE_CHAR_MAX_VALUE];
	uint8_t PASSWORD_LEN;
	int8_t PASSWORD[UNSIGNE_CHAR_MAX_VALUE];
};


//服务器鉴定后发出如下回应：
//
//鉴定协议版本	鉴定状态
//1					1
//
//
//其中鉴定状态 0x00 表示成功，0x01 表示失败。
struct S5Msg_S2C_Password
{
	uint8_t VER;
	uint8_t RET;
};