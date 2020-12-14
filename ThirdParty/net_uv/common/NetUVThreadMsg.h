#pragma once

#include "../base/Macros.h"

NS_NET_UV_BEGIN

//��Ϣ����
enum class NetThreadMsgType : uint32_t
{
	CONNECT_FAIL,		//����ʧ��
	CONNECT_TIMOUT,		//���ӳ�ʱ
	CONNECT_SESSIONID_EXIST,//�ỰID�Ѵ��ڣ���������IP�Ͷ˿ں�֮ǰ�Ự��һ��
	CONNECT_ING,		//��������
	CONNECT,			//���ӳɹ�
	NEW_CONNECT,		//������
	DIS_CONNECT,		//�Ͽ�����
	EXIT_LOOP,			//�˳�loop
	RECV_DATA,			//�յ���Ϣ
	REMOVE_SESSION,		//�Ƴ��Ự
};

class Session;

#pragma pack(4)
struct NetThreadMsg
{
	NetThreadMsgType msgType;
	Session* pSession;
	char* data;
	uint32_t dataLen;
};
#pragma pack()

NS_NET_UV_END
