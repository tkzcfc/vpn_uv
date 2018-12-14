#pragma once

#include <cstdint>
#include <string>

// ������󳤶�
#define DOMAIN_NAME_MAX_LENG 256

#define UNSIGNE_CHAR_MAX_VALUE 255

#define IPV4_LEN 4
#define IPV6_LEN 16

///http://www.cnblogs.com/yinzhengjie/p/7357860.html

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//������SOCKS5��������TCP���Ӻ�ͻ�����Ҫ�ȷ���������Э�̰汾����֤��ʽ����ʽΪ�����ֽ�Ϊ��λ����
//VER	NMETHODS	METHODS
//1	1	1 - 255
//
//
//VER��SOCKS�汾������Ӧ����0x05��
//NMETHODS��METHODS���ֵĳ��ȣ�
//METHODS�ǿͻ���֧�ֵ���֤��ʽ�б�ÿ������ռ1�ֽڡ���ǰ�Ķ����ǣ�
//0x00 ����Ҫ��֤
//0x01 GSSAPI
//0x02 �û�����������֤
//0x03 - 0x7F��IANA���䣨������
//0x80 - 0xFEΪ˽�˷�������
//0xFF �޿ɽ��ܵķ���
struct S5Msg_C2S_Verification
{
	uint8_t VER;
	uint8_t NMETHODS;
	uint8_t METHODS[UNSIGNE_CHAR_MAX_VALUE];
};

//�������ӿͻ����ṩ�ķ�����ѡ��һ����ͨ��������Ϣ֪ͨ�ͻ��ˣ����ֽ�Ϊ��λ����
//VER	METHOD
//1		1
//
//
//VER��SOCKS�汾������Ӧ����0x05��
//METHOD�Ƿ����ѡ�еķ������������0xFF��ʾû��һ����֤������ѡ�У��ͻ�����Ҫ�ر����ӡ�
struct S5Msg_S2C_Verification
{
	uint8_t VER;
	uint8_t METHOD;
};



//////////////////////////////////////////////////////////������Ϣ//////////////////////////////////////////////////////////

//֮��ͻ��˺ͷ���˸���ѡ������֤��ʽִ�ж�Ӧ����֤����֤������ͻ��˾Ϳ��Է���������Ϣ�������֤�����������װҪ��������밴�շ���������ķ�ʽ���з�װ��
//
//SOCKS5�����ʽ�����ֽ�Ϊ��λ����
//
//VER	CMD	RSV	ATYP	DST.ADDR	DST.PORT
//1	1	0x00	1	��̬	2
//
//
//VER��SOCKS�汾������Ӧ����0x05��
//CMD��SOCK��������
//0x01��ʾCONNECT����
//0x02��ʾBIND����
//0x03��ʾUDPת��
//RSV 0x00������
//ATYP DST.ADDR����
//0x01 IPv4��ַ��DST.ADDR����4�ֽڳ���
//0x03������DST ADDR���ֵ�һ���ֽ�Ϊ�������ȣ�DST.ADDRʣ�������Ϊ������û��\0��β��
//0x04 IPv6��ַ��16���ֽڳ��ȡ�
//DST.ADDR Ŀ�ĵ�ַ
//DST.PORT �����ֽ����ʾ��Ŀ�Ķ˿�
struct S5Msg_C2S_Request
{
	uint8_t VER;
	uint8_t CMD;
	uint8_t RSV; // 0x00
	uint8_t ATYP;// ��ַ����
	int8_t	DST_ADDR[DOMAIN_NAME_MAX_LENG];
	uint16_t DST_PORT;
};

//�����������¸�ʽ��Ӧ�ͻ��˵��������ֽ�Ϊ��λ����
//
//VER	REP	RSV	ATYP	BND.ADDR	BND.PORT
//1	1	0x00	1	��̬	2
//
//
//VER��SOCKS�汾������Ӧ����0x05��
//REPӦ���ֶ�
//0x00��ʾ�ɹ�
//0x01��ͨSOCKS����������ʧ��
//0x02���й�����������
//0x03���粻�ɴ�
//0x04�������ɴ�
//0x05���ӱ���
//0x06 TTL��ʱ
//0x07��֧�ֵ�����
//0x08��֧�ֵĵ�ַ����
//0x09 - 0xFFδ����
//RSV 0x00������
//ATYP BND.ADDR����
//0x01 IPv4��ַ��DST.ADDR����4�ֽڳ���
//0x03������DST.ADDR���ֵ�һ���ֽ�Ϊ�������ȣ�DST.ADDRʣ�������Ϊ������û��\0��β��
//0x04 IPv6��ַ��16���ֽڳ��ȡ�
//BND.ADDR �������󶨵ĵ�ַ
//BND.PORT �����ֽ����ʾ�ķ������󶨵Ķ˿�
struct S5Msg_S2C_Request
{
	uint8_t VER;
	uint8_t REP;
	uint8_t RSV; // 0x00
	uint8_t ATYP;
	int8_t BND_ADDR[DOMAIN_NAME_MAX_LENG];
	uint16_t BND_PORT;
};

//////////////////////////////////////////////////////////����У��//////////////////////////////////////////////////////////

//SOCKS5 �û���������֤��ʽ
//�ڿͻ��ˡ������Э��ʹ���û���������֤�󣬿ͻ��˷����û������룬��ʽΪ�����ֽ�Ϊ��λ����
//
//����Э��汾	�û�������	�û���	���볤��	����
//1					1	     ��̬	  1	        ��̬
//
//
//����Э��汾ĿǰΪ 0x01 ��
struct S5Msg_C2S_Password
{
	uint8_t VER;//0x01
	uint8_t USER_NAME_LEN;
	int8_t USER_NAME[UNSIGNE_CHAR_MAX_VALUE];
	uint8_t PASSWORD_LEN;
	int8_t PASSWORD[UNSIGNE_CHAR_MAX_VALUE];
};


//�����������󷢳����»�Ӧ��
//
//����Э��汾	����״̬
//1					1
//
//
//���м���״̬ 0x00 ��ʾ�ɹ���0x01 ��ʾʧ�ܡ�
struct S5Msg_S2C_Password
{
	uint8_t VER;
	uint8_t RET;
};