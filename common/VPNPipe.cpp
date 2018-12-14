#include "VPNPipe.h"
#include <zlib/zlib.h>

VPNPipe::VPNPipe(TYPE type)
	: m_pipeRecvCall(nullptr)
	, m_pipeCloseCall(nullptr)
	, m_pipeReadyCall(nullptr)
	, m_isStart(false)
	, m_readyStatusCache(false)
	, m_ip("")
	, m_port(0)
	, m_uniqueID(0)
{
	m_bufferRes = new unsigned char[1024 * 1024];
	m_bufferDes = new unsigned char[1024 * 1024];
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
}

VPNPipe::~VPNPipe()
{
	delete[]m_bufferRes;
	delete[]m_bufferDes;
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
		m_isStart = m_svr->startServer(ip, port, false);
	}
	if (m_client)
	{
		for (int32_t i = 0; i < 2; ++i)
		{
			m_client->connect(ip, port, m_uniqueID++);
		}
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

	MSG_P_Base* msg = (MSG_P_Base*)data;

	if (m_sessionIDMap.find(msg->sessionId) == m_sessionIDMap.end())
	{
		m_sessionIDMap[msg->sessionId] = getWriteSessionID();
	}

	uint32_t sessionID = m_sessionIDMap[msg->sessionId];
	if (msg->msgType == PIPEMSG_TYPE::C2S_DISCONNECT || msg->msgType == PIPEMSG_TYPE::S2C_DISCONNECT)
	{
		m_sessionIDMap.erase(msg->sessionId);
	}

	memcpy(m_bufferRes, data, len);

	uLongf desLen;
	int nError = compress(m_bufferDes, &desLen, m_bufferRes, len);
	if (nError != Z_OK)
	{
		printf("compress error\n");
		return;
	}
	//printf("___send %d\n", desLen);
	if (m_type == TYPE::SERVER)
	{
		m_svr->send(m_sessionIDMap[msg->sessionId], (char*)m_bufferDes, desLen);
	}
	else
	{
		m_client->send(m_sessionIDMap[msg->sessionId], (char*)m_bufferDes, desLen);
	}
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
	printf("svr pipe newconnect %d %d\n", session->getSessionID(), m_connectSessionIDArr.size());
}

void VPNPipe::on_ServerRecvCall(Server* svr, Session* session, char* data, uint32_t len)
{
	//printf("___recv %d\n", len);
	memcpy(m_bufferDes, data, len);

	uLongf unSize;
	int nError = uncompress(m_bufferRes, &unSize, m_bufferDes, len);
	if (nError != Z_OK)
	{
		printf("uncompress error\n");
		return;
	}

	MSG_P_Base* msg = (MSG_P_Base*)m_bufferRes;
	m_sessionIDMap[msg->sessionId] = session->getSessionID();

	if (msg->msgType == PIPEMSG_TYPE::C2S_DISCONNECT || msg->msgType == PIPEMSG_TYPE::S2C_DISCONNECT)
	{
		m_sessionIDMap.erase(msg->sessionId);
	}
	m_pipeRecvCall((char*)m_bufferRes, unSize);
}

void VPNPipe::on_ServerDisconnectCall(Server* svr, Session* session)
{
	m_connectSessionIDArr.erase(std::find(m_connectSessionIDArr.begin(), m_connectSessionIDArr.end(), session->getSessionID()));

	for (auto &it : m_sessionIDMap)
	{
		if (it.second == session->getSessionID())
		{
			MSG_P_Base msg;
			msg.sessionId = it.first;
			msg.msgType = PIPEMSG_TYPE::C2S_DISCONNECT;
			m_pipeRecvCall((char*)&msg, sizeof(MSG_P_Base));
			m_sessionIDMap.erase(it.first);
			break;
		}
	}
	printf("svr pipe disconnect %d %d\n", session->getSessionID(), m_connectSessionIDArr.size());
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
		printf("cli pipe session[%d], connect suc %d\n", session->getSessionID(), m_connectSessionIDArr.size());
	}
	else
	{
		printf("cli pipe session[%d], connect fail\n", session->getSessionID());
	}
}

void VPNPipe::on_ClientDisconnectCall(Client* client, Session* session)
{
	m_connectSessionIDArr.erase(std::find(m_connectSessionIDArr.begin(), m_connectSessionIDArr.end(), session->getSessionID()));
	
	if (m_readyStatusCache && m_connectSessionIDArr.empty())
	{
		m_readyStatusCache = false;
		if (m_pipeReadyCall != NULL)
		{
			m_pipeReadyCall(m_readyStatusCache);
		}
	}

	for (auto &it : m_sessionIDMap)
	{
		if (it.second == session->getSessionID())
		{
			MSG_P_Base msg;
			msg.sessionId = it.first;
			msg.msgType = PIPEMSG_TYPE::S2C_DISCONNECT;
			m_pipeRecvCall((char*)&msg, sizeof(MSG_P_Base));
			m_sessionIDMap.erase(it.first);
			break;
		}
	}
	printf("cli pipe session[%d], disconnect %d\n", session->getSessionID(), m_connectSessionIDArr.size());
}

void VPNPipe::on_ClientRecvCall(Client* client, Session* session, char* data, uint32_t len)
{
	//printf("___recv %d\n", len);
	memcpy(m_bufferDes, data, len);

	uLongf unSize;
	int nError = uncompress(m_bufferRes, &unSize, m_bufferDes, len);
	if (nError != Z_OK)
	{
		printf("uncompress error\n");
		return;
	}

	MSG_P_Base* msg = (MSG_P_Base*)m_bufferRes;
	if (msg->msgType == PIPEMSG_TYPE::C2S_DISCONNECT || msg->msgType == PIPEMSG_TYPE::S2C_DISCONNECT)
	{
		m_sessionIDMap.erase(msg->sessionId);
	}
	m_pipeRecvCall((char*)m_bufferRes, unSize);
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

	if (m_type == TYPE::CLIENT && minCount > 0 && m_uniqueID < VPN_PIPE_MAX_SESSION_COUNT)
	{
		m_client->connect(m_ip.c_str(), m_port, m_uniqueID++);
		printf("\n\nm_uniqueID = %d\n\n", m_uniqueID);
	}

	return minSessionID;
}