#include "VPNPipe.h"

VPNPipe::VPNPipe(TYPE type)
	: m_pipeRecvCall(nullptr)
	, m_pipeCloseCall(nullptr)
	, m_pipeReadyCall(nullptr)
	, m_isStart(false)
	, m_readyStatusCache(false)
	, m_ip("")
	, m_port(0)
	, m_uniqueID(0)
	, m_sessionCount(0)
	, m_transmittedSize(0)
	, m_net_uv_transmittedSize(0)
	, m_checkTime(10)
{
#if USE_SNAPPY 
#else
	m_buffer = new unsigned char[1024 * 1024];
#endif
	m_type = type;
	if (type == TYPE::SERVER)
	{
		m_svr = std::make_unique<PipeServer>();
		m_svr->setCloseCallback(std::bind(&VPNPipe::on_ServerCloseCall, this, std::placeholders::_1));
		m_svr->setNewConnectCallback(std::bind(&VPNPipe::on_ServerNewConnectCall, this, std::placeholders::_1, std::placeholders::_2));
		m_svr->setRecvCallback(std::bind(&VPNPipe::on_ServerRecvCall, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4));
		m_svr->setDisconnectCallback(std::bind(&VPNPipe::on_ServerDisconnectCall, this, std::placeholders::_1, std::placeholders::_2));
	}
	else
	{
		m_client = std::make_unique<PipeClient>();
		m_client->setConnectCallback(std::bind(&VPNPipe::on_ClientConnectCall, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
		m_client->setDisconnectCallback(std::bind(&VPNPipe::on_ClientDisconnectCall, this, std::placeholders::_1, std::placeholders::_2));
		m_client->setRecvCallback(std::bind(&VPNPipe::on_ClientRecvCall, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4));
		m_client->setClientCloseCallback(std::bind(&VPNPipe::on_ClientCloseCall, this, std::placeholders::_1));
		m_client->setRemoveSessionCallback(std::bind(&VPNPipe::on_ClientRemoveSessionCall, this, std::placeholders::_1, std::placeholders::_2));
		m_client->setAutoReconnect(true);
	}
	m_lastTime = std::chrono::high_resolution_clock::now();
}

VPNPipe::~VPNPipe()
{
#if USE_SNAPPY 
#else
	delete[]m_buffer;
#endif
}

bool VPNPipe::start(const char* ip, uint32_t port)
{
	if (m_isStart)
	{
		assert(0);
		return false;
	}
	m_ip = ip;
	m_port = port;
	if (m_svr)
	{
		m_isStart = m_svr->startServer(ip, port, false, 0xFFFF);
	}
	if (m_client)
	{
		addConnect();
		m_isStart = true;
	}
	return m_isStart;
}

void VPNPipe::stop()
{
	m_isStart = false;
	if (m_svr != NULL)
	{
		m_svr->stopServer();
	}
	if (m_client)
	{
		m_client->closeClient();
	}
}

void VPNPipe::send(char* data, uint32_t len)
{
	if (!m_isStart)
	{
		return;
	}

	if (m_client && m_connectSessionIDArr.empty())
	{
		return;
	}

	MSG_P_Base* msg = (MSG_P_Base*)data;

	if (m_sessionIDMap.find(msg->sessionId) == m_sessionIDMap.end())
	{
		m_sessionIDMap[msg->sessionId] = getWriteSessionID();
	}

	uint32_t sessionID = m_sessionIDMap[msg->sessionId];
	if (msg->msgType == PIPEMSG_TYPE::C2S_DISCONNECT || msg->msgType == PIPEMSG_TYPE::S2C_DISCONNECT)
	{
		eraseConnect(msg->sessionId);
	}

#if USE_SNAPPY
	snappy::string out;
	if (!snappy::Compress(data, len, &out))
	{
		printf("snappy::Compress Error\n");
		return;
	}

	if (m_type == TYPE::SERVER)
	{
		m_svr->send(sessionID, (char*)out.c_str(), out.size());
	}
	else
	{
		m_client->send(sessionID, (char*)out.c_str(), out.size());
	}
#else
	rc4_init(&m_state, rc4_key, rc4_key_len);
	rc4_crypt(&m_state, (unsigned char*)data, m_buffer, len);
	if (m_type == TYPE::SERVER)
	{
		m_svr->send(sessionID, (char*)m_buffer, len);
	}
	else
	{
		m_client->send(sessionID, (char*)m_buffer, len);
	}
#endif
}

void VPNPipe::onRecvData(Session*session, char* data, uint32_t len)
{
	m_net_uv_transmittedSize += len;

#if USE_SNAPPY
	snappy::string out;
	if (!snappy::Uncompress(data, len, &out))
	{
		printf("snappy::Uncompress error\n");
		return;
	}
	m_transmittedSize += out.size();

	MSG_P_Base* msg = (MSG_P_Base*)out.c_str();
	m_sessionIDMap[msg->sessionId] = session->getSessionID();

	if (msg->msgType == PIPEMSG_TYPE::C2S_DISCONNECT || msg->msgType == PIPEMSG_TYPE::S2C_DISCONNECT)
	{
		eraseConnect(msg->sessionId);
	}
	m_pipeRecvCall((char*)out.c_str(), out.size());
#else
	rc4_init(&m_state, rc4_key, rc4_key_len);
	rc4_crypt(&m_state, (unsigned char*)data, m_buffer, len);

	m_transmittedSize += len;

	MSG_P_Base* msg = (MSG_P_Base*)m_buffer;
	m_sessionIDMap[msg->sessionId] = session->getSessionID();

	if (msg->msgType == PIPEMSG_TYPE::C2S_DISCONNECT || msg->msgType == PIPEMSG_TYPE::S2C_DISCONNECT)
	{
		eraseConnect(msg->sessionId);
	}
	m_pipeRecvCall((char*)m_buffer, len);
#endif
}

void VPNPipe::updateFrame()
{
	if (m_client != NULL)
	{
		m_client->updateFrame();
	}
	if (m_svr != NULL)
	{
		m_svr->updateFrame();
	}
	std::chrono::time_point<std::chrono::high_resolution_clock> curTime = std::chrono::high_resolution_clock::now();
	int64_t milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(curTime - m_lastTime).count();
	if (milliseconds > 1000)
	{
		if (m_transmittedSize > 0U)
		{
			if (m_transmittedSize < 1024)
			{
				float speed = (float)m_transmittedSize;
				float uv_speed = (float)m_net_uv_transmittedSize;
				printf("%0.2fbytes/s \t %0.2fbytes/s\n", speed, uv_speed);
			}
			else if (m_transmittedSize < 1024 * 1024)
			{
				float speed = (float)m_transmittedSize / 1024.0f;
				float uv_speed = (float)m_net_uv_transmittedSize / 1024.0f;
				printf("%0.2fkb/s \t %0.2fkb/s\n", speed, uv_speed);
			}
			else
			{
				float speed = (float)m_transmittedSize / (1024.0f * 1024.0f);
				float uv_speed = (float)m_net_uv_transmittedSize / (1024.0f * 1024.0f);
				printf("%0.2fmb/s \t %0.2fmb/s\n", speed, uv_speed);
			}
		}		
		m_transmittedSize = 0;
		m_net_uv_transmittedSize = 0;
		m_lastTime = curTime;
		m_checkTime--;
		if (m_checkTime <= 0)
		{
			checkInvalidSession();
			m_checkTime = 20;
		}
	}
}

void VPNPipe::on_ServerCloseCall(Server* svr)
{
	m_connectSessionIDArr.clear();
	if (m_pipeCloseCall != nullptr)
	{
		m_pipeCloseCall();
	}
}

void VPNPipe::on_ServerNewConnectCall(Server* svr, Session* session)
{
	auto it = std::find(m_connectSessionIDArr.begin(), m_connectSessionIDArr.end(), session->getSessionID());
	if (it == m_connectSessionIDArr.end())
	{
		m_connectSessionIDArr.push_back(session->getSessionID());
	}
	printf("svr pipe newconnect %lu %lu\n", session->getSessionID(), m_connectSessionIDArr.size());
}

void VPNPipe::on_ServerRecvCall(Server* svr, Session* session, char* data, uint32_t len)
{
	onRecvData(session, data, len);
}

void VPNPipe::on_ServerDisconnectCall(Server* svr, Session* session)
{
	disconnectSession(session->getSessionID());
	printf("svr pipe disconnect %lu %lu\n", session->getSessionID(), m_connectSessionIDArr.size());
}

void VPNPipe::on_ClientConnectCall(Client* client, Session* session, int32_t status)
{
	if (status == 1)
	{
		auto it = std::find(m_connectSessionIDArr.begin(), m_connectSessionIDArr.end(), session->getSessionID());
		if (it == m_connectSessionIDArr.end())
		{
			m_connectSessionIDArr.push_back(session->getSessionID());
		}

		if (!m_readyStatusCache && m_connectSessionIDArr.empty() == false)
		{
			m_readyStatusCache = true;
			if (m_pipeReadyCall != NULL)
			{
				m_pipeReadyCall(m_readyStatusCache);
			}
		}
		printf("cli pipe session[%lu], connect suc %lu\n", session->getSessionID(), m_connectSessionIDArr.size());
	}
	else
	{
		printf("cli pipe session[%lu], connect fail\n", session->getSessionID());
	}
}

void VPNPipe::on_ClientDisconnectCall(Client* client, Session* session)
{
	disconnectSession(session->getSessionID());

	if (getFreeSessionCount() >= VPN_PIPE_PRE_SESSION_COUNT)
	{
		m_sessionCount--;
		client->removeSession(session->getSessionID());
		printf("cli pipe remove session[%d], cur session count = [%d]\n", session->getSessionID(), m_sessionCount);
	}

	printf("cli pipe session[%lu], disconnect %lu\n", session->getSessionID(), m_connectSessionIDArr.size());
}

void VPNPipe::on_ClientRecvCall(Client* client, Session* session, char* data, uint32_t len)
{
	onRecvData(session, data, len);
}

void VPNPipe::on_ClientCloseCall(Client* client)
{
	m_connectSessionIDArr.clear();
	if (m_pipeCloseCall != nullptr)
	{
		m_pipeCloseCall();
	}
}

void VPNPipe::on_ClientRemoveSessionCall(Client* client, Session* session)
{}

void VPNPipe::disconnectSession(uint32_t sessionID)
{
	for (auto it = m_connectSessionIDArr.begin(); it != m_connectSessionIDArr.end();)
	{
		if (*it == sessionID)
		{
			it = m_connectSessionIDArr.erase(it);
		}
		else
		{
			it++;
		}
	}

	for (auto it = m_sessionIDMap.begin(); it != m_sessionIDMap.end();)
	{
		if (it->second == sessionID)
		{
			MSG_P_Base msg;
			msg.sessionId = it->first;
			if (m_type == TYPE::CLIENT)
			{
				msg.msgType = PIPEMSG_TYPE::S2C_DISCONNECT;
			}
			else
			{
				msg.msgType = PIPEMSG_TYPE::C2S_DISCONNECT;
			}

			it = m_sessionIDMap.erase(it);

			m_pipeRecvCall((char*)&msg, sizeof(MSG_P_Base));
		}
		else
		{
			++it;
		}
	}
}

void VPNPipe::addConnect()
{
	if (m_type == TYPE::CLIENT && m_sessionCount < VPN_PIPE_MAX_SESSION_COUNT)
	{
		auto freeCount = getFreeSessionCount();
		for (auto i = freeCount; i < VPN_PIPE_PRE_SESSION_COUNT; ++i)
		{
			if (m_sessionCount >= VPN_PIPE_MAX_SESSION_COUNT)
			{
				break;
			}
			m_sessionCount++;
			m_client->connect(m_ip.c_str(), m_port, m_uniqueID++);
		}
	}
}

uint32_t VPNPipe::getWriteSessionID()
{
	if (m_connectSessionIDArr.empty())
	{
		return 0;
	}

	uint32_t minSessionID = 0;
	uint32_t minCount = 1000000;
	for (auto &it : m_connectSessionIDArr)
	{
		uint32_t count = 0;
		for (auto& it_s : m_sessionIDMap)
		{
			if (it_s.second == it)
			{
				count++;
			}
		}
		if (count == 0)
		{
			return it;
		}
		if (minCount > count)
		{
			minCount = count;
			minSessionID = it;
		}
	}

	if (m_type == TYPE::CLIENT && minCount > 0)
	{
		addConnect();
	}

	return minSessionID;
}

uint32_t VPNPipe::getFreeSessionCount()
{
	if (m_connectSessionIDArr.empty())
	{
		return 0;
	}

	uint32_t freeCount = 0;
	for (auto &it : m_connectSessionIDArr)
	{
		uint32_t count = 0;
		for (auto& it_s : m_sessionIDMap)
		{
			if (it_s.second == it)
			{
				count++;
			}
		}
		if (count == 0)
		{
			freeCount++;
		}
	}
	return freeCount;
}

uint32_t VPNPipe::getSessionRefCount(uint32_t sessionID)
{
	if (m_connectSessionIDArr.empty())
	{
		return 0;
	}

	uint32_t refCount = 0;
	for (auto& it_s : m_sessionIDMap)
	{
		if (it_s.second == sessionID)
		{
			refCount++;
		}
	}

	return refCount;
}

void VPNPipe::eraseConnect(uint32_t msgSessionID)
{
	auto it = m_sessionIDMap.find(msgSessionID);
	if (it != m_sessionIDMap.end())
	{
		auto s = it->second;
		m_sessionIDMap.erase(it);
		if (m_type == TYPE::CLIENT)
		{
			tryDisconnectSession(s);
		}
	}
}

void VPNPipe::tryDisconnectSession(uint32_t sessionID)
{
	if (m_type != TYPE::CLIENT)
	{
		return;
	}

	if (getSessionRefCount(sessionID) == 0)
	{
		m_client->disconnect(sessionID);
	}
}

void VPNPipe::checkInvalidSession()
{
	if (m_client == NULL)
	{
		return;
	}

	if (m_connectSessionIDArr.empty())
	{
		return;
	}

	uint32_t freeCount = 0;
	for (auto it = m_connectSessionIDArr.begin(); it != m_connectSessionIDArr.end(); )
	{
		if (getSessionRefCount(*it) == 0)
		{
			freeCount++;
			if (freeCount > VPN_PIPE_PRE_SESSION_COUNT)
			{
				m_client->removeSession(*it);
				it = m_connectSessionIDArr.erase(it);
			}
			else
			{
				it++;
			}
		}
		else
		{
			it++;
		}
	}
}

