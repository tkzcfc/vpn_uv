#pragma once

#include "../base/Common.h"
#include "../base/Socket.h"
#include "../base/Runnable.h"
#include "../base/Misc.h"
#include "../base/Session.h"
#include "../base/SessionManager.h"
#include "../base/Mutex.h"
#include "../base/Client.h"
#include "../base/Server.h"
#include "../common/NetUVThreadMsg.h"
#include "../common/NetHeart.h"
#include "KCPConfig.h"

NS_NET_UV_BEGIN

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// ��Ϣ��ͷ
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////

struct KCPMsgHead
{
	uint32_t len;// ��Ϣ���ȣ����������ṹ��
#if KCP_OPEN_UV_THREAD_HEARTBEAT == 1
	NET_HEART_TYPE tag;// ��Ϣ���
#endif
};

NS_NET_UV_END
