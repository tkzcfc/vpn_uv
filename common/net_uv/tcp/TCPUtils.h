#pragma once

#include "TCPCommon.h"

NS_NET_UV_BEGIN

//����
char* tcp_uv_encode(const char* data, uint32_t len, uint32_t &outLen);
//����
char* tcp_uv_decode(const char* data, uint32_t len, uint32_t &outLen);
// �������
uv_buf_t* tcp_packageData(char* data, uint32_t len, int32_t* bufCount);
// ���������Ϣ
char* tcp_packageHeartMsgData(NET_HEART_TYPE msg, uint32_t* outBufSize);

NS_NET_UV_END