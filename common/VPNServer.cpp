#include "VPNServer.h"


VPNServer::VPNServer()
	: m_clientUniqueSessionID(0)
	, m_stopCall(nullptr)
	, m_clientStop(true)
	, m_pipeStop(true)
{}

VPNServer::~VPNServer()
{}

bool VPNServer::start(const char* ip, uint32_t port)
{
	if (m_client != NULL)
	{
		return false;
	}

	m_pipe = std::make_unique<VPNPipe>(VPNPipe::TYPE::SERVER);
	m_pipe->setRecvCallback(std::bind(&VPNServer::on_pipeRecvCallback, this, std::placeholders::_1, std::placeholders::_2));
	m_pipe->setCloseCallback([this]() {
		this->m_pipeStop = true;
		this->tryCallStop();
	});
	if (!m_pipe->start(ip, port))
	{
		m_pipe = NULL;
		return false;
	}
	m_client = std::make_unique<TCPClient>();
	m_client->setConnectCallback(std::bind(&VPNServer::on_ClientConnectCall, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
	m_client->setDisconnectCallback(std::bind(&VPNServer::on_ClientDisconnectCall, this, std::placeholders::_1, std::placeholders::_2));
	m_client->setRecvCallback(std::bind(&VPNServer::on_ClientRecvCall, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4));
	m_client->setClientCloseCallback(std::bind(&VPNServer::on_ClientCloseCall, this, std::placeholders::_1));
	m_client->setRemoveSessionCallback(std::bind(&VPNServer::on_ClientRemoveSessionCall, this, std::placeholders::_1, std::placeholders::_2));
	m_client->setAutoReconnect(false);

	m_clientStop = false;
	m_pipeStop = false;

	return true;
}

void VPNServer::stop(const std::function<void()>& stopCall)
{
	m_stopCall = stopCall;
	if (m_client)
	{
		m_client->closeClient();
	}
	if (m_pipe)
	{
		m_pipe->stop();
	}
}

void VPNServer::tryCallStop()
{
	if (m_clientStop && m_pipeStop)
	{
		m_client = NULL;
		m_pipe = NULL;
		if (m_stopCall != NULL)
		{
			m_stopCall();
		}
	}
}

void VPNServer::updateFrame()
{
	if (m_client)
	{
		m_client->updateFrame();
	}
	if (m_pipe)
	{
		m_pipe->updateFrame();
	}
}

void VPNServer::on_ClientConnectCall(Client* client, Session* session, int32_t status)
{
	printf("connect to %s %s\n", session->getIp().c_str(), status == 1 ? "true" : "false");

	auto it = m_sessionIDMap.find(session->getSessionID());
	if (it != m_sessionIDMap.end())
	{
		MSG_P_S2C_Request req(it->second);
		req.ret = status;
		m_pipe->send((char*)&req, sizeof(MSG_P_S2C_Request));
	}

	if(status != 1)
	{
		client->removeSession(session->getSessionID());
	}
}

void VPNServer::on_ClientDisconnectCall(Client* client, Session* session)
{
	//printf("disconnect to %s\n", session->getIp().c_str());
	client->removeSession(session->getSessionID());
}

void VPNServer::on_ClientRecvCall(Client* client, Session* session, char* data, uint32_t len)
{
	auto it = m_sessionIDMap.find(session->getSessionID());
	if (it != m_sessionIDMap.end())
	{
		printf("send [%d]\n", len);

		char* sendData = new char[sizeof(MSG_P_Base) + len];
		((MSG_P_Base*)sendData)->sessionId = it->second;
		((MSG_P_Base*)sendData)->msgType = PIPEMSG_TYPE::S2C_SENDDATA;
		memcpy(sendData + sizeof(MSG_P_Base), data, len);

		m_pipe->send(sendData, sizeof(MSG_P_Base) + len);

		delete[]sendData;
	}
}

void VPNServer::on_ClientCloseCall(Client* client)
{
	m_sessionIDMap.clear();
	m_clientStop = true;
	tryCallStop();
}

void VPNServer::on_ClientRemoveSessionCall(Client* client, Session* session)
{
	m_sessionIDMap.erase(session->getSessionID());
}

/// pipe
void VPNServer::on_pipeRecvCallback(char* data, uint32_t len)
{
	MSG_P_Base* msg = (MSG_P_Base*)data;
	switch (msg->msgType)
	{
	case PIPEMSG_TYPE::C2S_REQUEST:
	{
		//printf("pipe C2S_REQUEST\n");
		MSG_P_C2S_Request* reqMsg = (MSG_P_C2S_Request*)data;
		m_client->connect(reqMsg->szIP, reqMsg->port, m_clientUniqueSessionID);
		m_sessionIDMap[m_clientUniqueSessionID] = msg->sessionId;
		m_clientUniqueSessionID++;
	}break;
	case PIPEMSG_TYPE::C2S_SENDDATA:
	{
		//printf("pipe C2S_SENDDATA\n");
		printf("recv [%d]\n", len - sizeof(MSG_P_Base));

		for (auto &it : m_sessionIDMap)
		{
			if (it.second == msg->sessionId)
			{
				m_client->send(it.first, data + sizeof(MSG_P_Base), len - sizeof(MSG_P_Base));
				break;
			}
		}
	}break;
	case PIPEMSG_TYPE::C2S_DISCONNECT:
	{
		//printf("pipe C2S_DISCONNECT\n");
		for (auto &it : m_sessionIDMap)
		{
			if (it.second == msg->sessionId)
			{
				m_client->disconnect(it.first);
				break;
			}
		}
	}break;
	default:
		printf("Î´ÖªÏûÏ¢ID:%d\n", msg->msgType);
		break;
	}
}

