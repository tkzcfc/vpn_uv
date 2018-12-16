#include "TCPUtils.h"
#include "TCPCommon.h"

NS_NET_UV_BEGIN

// ����Key
const char* tcp_uv_encodeKey = TCP_UV_ENCODE_KEY;
const uint32_t tcp_uv_encodeKeyLen = (uint32_t)strlen(tcp_uv_encodeKey);

const static uint32_t tcp_uv_hashlen = sizeof(unsigned int);


const static uint32_t tcp_msg_headlen = sizeof(TCPMsgHead);



// ����
// ����ǰ ��|-DATA-|
// ���ܺ� ��|-��MD5��DATA+����key������hashֵ-|-DATA-|
char* tcp_uv_encode(const char* data, uint32_t len, uint32_t &outLen)
{
	MD5 M;

	outLen = tcp_uv_hashlen + len;

	char* r = (char*)fc_malloc(outLen + tcp_uv_encodeKeyLen);

	memcpy(r + tcp_uv_hashlen, data, len);
	memcpy(r + outLen, tcp_uv_encodeKey, tcp_uv_encodeKeyLen);

	M.reset();
	M.update(r + tcp_uv_hashlen, len + tcp_uv_encodeKeyLen);

	auto md5s = M.toString();

	auto hashvalue = net_getBufHash(md5s.c_str(), md5s.size());
	memcpy(r, &hashvalue, tcp_uv_hashlen);

	return r;
}

// ����
char* tcp_uv_decode(const char* data, uint32_t len, uint32_t &outLen)
{
	outLen = 0;

	MD5 M;

	int32_t datalen = len - tcp_uv_hashlen;

	char* p = (char*)fc_malloc(datalen + tcp_uv_encodeKeyLen + 1);

	memcpy(p, data + tcp_uv_hashlen, datalen);
	memcpy(p + datalen, tcp_uv_encodeKey, tcp_uv_encodeKeyLen);

	M.reset();
	M.update(p, datalen + tcp_uv_encodeKeyLen);

	auto md5s = M.toString();

	uint32_t hashvalue = net_getBufHash(md5s.c_str(), (uint32_t)md5s.size());
	if (hashvalue == *(uint32_t*)(data))
	{
		outLen = datalen;
	}

	//�����ݲ��Ϸ�
	if (outLen == 0)
	{
		fc_free(p);
		p = NULL;
	}
	else
	{
		p[datalen] = '\0';
	}
	return p;
}





// �������
uv_buf_t* tcp_packageData(char* data, uint32_t len, int32_t* bufCount)
{
	*bufCount = 0;
	if (data == NULL || len <= 0)
	{
		return NULL;
	}

#if TCP_USE_NET_UV_MSG_STRUCT == 0

	*bufCount = 1;

	uv_buf_t* outBuf = (uv_buf_t*)fc_malloc(sizeof(uv_buf_t));
	outBuf->base = (char*)fc_malloc(len);
	memcpy(outBuf->base, data, len);
	outBuf->len = len;
	
	return outBuf;
#else
	if (len > TCP_BIG_MSG_MAX_LEN)
	{
#if defined (WIN32) || defined(_WIN32)
		MessageBox(NULL, TEXT("��Ϣ�����������"), TEXT("����"), MB_OK);
#else
		printf("��Ϣ�����������");
#endif
		assert(0);
		return NULL;
	}

#if TCP_UV_OPEN_MD5_CHECK == 1

	uint32_t encodelen = 0;
	char* encodedata = tcp_uv_encode(data, len, encodelen);
	if (encodedata == NULL)
	{
		assert(0);
		return NULL;
	}
	uint32_t sendlen = tcp_msg_headlen + encodelen;
	char* p = (char*)fc_malloc(sendlen);

	TCPMsgHead* h = (TCPMsgHead*)p;
	h->len = encodelen;
#if TCP_OPEN_UV_THREAD_HEARTBEAT == 1
	h->tag = NET_MSG_TYPE::MT_DEFAULT;
#endif
	memcpy(p + tcp_msg_headlen, encodedata, encodelen);

	fc_free(encodedata);
#else
	uint32_t sendlen = tcp_msg_headlen + len;
	char* p = (char*)fc_malloc(sendlen);
	TCPMsgHead* h = (TCPMsgHead*)p;
	h->len = len;
#if TCP_OPEN_UV_THREAD_HEARTBEAT == 1
	h->tag = NET_MSG_TYPE::MT_DEFAULT;
#endif
	memcpy(p + tcp_msg_headlen, data, len);
#endif
	uv_buf_t* outBuf = NULL;
	// ���ļ���Ƭ
	if (sendlen > TCP_WRITE_MAX_LEN)
	{
		*bufCount = sendlen / TCP_WRITE_MAX_LEN;
		if (sendlen % TCP_WRITE_MAX_LEN != 0)
		{
			*bufCount = *bufCount + 1;
		}

		outBuf = (uv_buf_t*)fc_malloc(sizeof(uv_buf_t) * (*bufCount));
		
		int32_t curIndex = 0;
		int32_t curArrIndex = 0;

		while (sendlen > 0)
		{
			if (sendlen < TCP_WRITE_MAX_LEN)
			{
				char* tmp = (char*)fc_malloc(sendlen);
				memcpy(tmp, p + curIndex, sendlen);

				(outBuf + curArrIndex)->base = tmp;
				(outBuf + curArrIndex)->len = sendlen;

				curArrIndex++;
				curIndex = curIndex + sendlen;
				sendlen = 0;
			}
			else
			{
				char* tmp = (char*)fc_malloc(TCP_WRITE_MAX_LEN);
				memcpy(tmp, p + curIndex, TCP_WRITE_MAX_LEN);

				(outBuf + curArrIndex)->base = tmp;
				(outBuf + curArrIndex)->len = TCP_WRITE_MAX_LEN;

				curArrIndex++;
				sendlen = sendlen - TCP_WRITE_MAX_LEN;
				curIndex = curIndex + TCP_WRITE_MAX_LEN;
			}
		}
		fc_free(p);
	}
	else
	{
		*bufCount = 1;

		outBuf = (uv_buf_t*)fc_malloc(sizeof(uv_buf_t));
		outBuf->base = p;
		outBuf->len = sendlen;
	}
	return outBuf;
#endif
}

// ���������Ϣ
char* tcp_packageHeartMsgData(NET_HEART_TYPE msg, unsigned int* outBufSize)
{
	*outBufSize = 0;
#if TCP_UV_OPEN_MD5_CHECK == 1
	uint32_t encodelen = 0;
	char* encodedata = tcp_uv_encode((char*)&msg, NET_HEARTBEAT_MSG_SIZE, encodelen);
	if (encodedata == NULL)
	{
		assert(0);
		return NULL;
	}
	uint32_t sendlen = tcp_msg_headlen + encodelen;
	char* p = (char*)fc_malloc(sendlen);
	if (p == NULL)
	{
		fc_free(encodedata);
		return NULL;
	}
	TCPMsgHead* h = (TCPMsgHead*)p;
	h->len = encodelen;
#if TCP_OPEN_UV_THREAD_HEARTBEAT == 1
	h->tag = NET_MSG_TYPE::MT_HEARTBEAT;
#endif
	memcpy(p + tcp_msg_headlen, encodedata, encodelen);

	fc_free(encodedata);
#else
	uint32_t sendlen = tcp_msg_headlen + NET_HEARTBEAT_MSG_SIZE;
	char* p = (char*)fc_malloc(sendlen);
	if (p == NULL)
	{
		return NULL;
	}
	TCPMsgHead* h = (TCPMsgHead*)p;
	h->len = NET_HEARTBEAT_MSG_SIZE;
#if TCP_OPEN_UV_THREAD_HEARTBEAT == 1
	h->tag = NET_MSG_TYPE::MT_HEARTBEAT;
#endif
	memcpy(p + tcp_msg_headlen, &msg, NET_HEARTBEAT_MSG_SIZE);
#endif

	*outBufSize = sendlen;

	return p;
}

NS_NET_UV_END