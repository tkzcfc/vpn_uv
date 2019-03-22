#include "Pure_TCPClient.h"

NS_NET_UV_BEGIN


enum 
{
	Pure_TCP_CLI_OP_CONNECT,			//	连接
	Pure_TCP_CLI_OP_SENDDATA,		// 发送数据
	Pure_TCP_CLI_OP_DISCONNECT,		// 断开连接
	Pure_TCP_CLI_OP_SET_KEEP_ALIVE,	//设置心跳
	Pure_TCP_CLI_OP_SET_NO_DELAY,	//设置NoDelay
	Pure_TCP_CLI_OP_CLIENT_CLOSE,	//客户端退出
	Pure_TCP_CLI_OP_REMOVE_SESSION,	//移除会话命令
	Pure_TCP_CLI_OP_DELETE_SESSION,	//删除会话
};

// 连接操作
struct Pure_TCPClientConnectOperation
{
	Pure_TCPClientConnectOperation() {}
	~Pure_TCPClientConnectOperation() {}
	std::string ip;
	uint32_t port;
	uint32_t sessionID;
};


//////////////////////////////////////////////////////////////////////////////////
Pure_TCPClient::Pure_TCPClient()
	: m_enableNoDelay(true)
	, m_enableKeepAlive(false)
	, m_keepAliveDelay(10)
	, m_isStop(false)
{
	uv_loop_init(&m_loop);
	
	m_clientStage = clientStage::START;
	
	startIdle();

	uv_timer_init(&m_loop, &m_clientUpdateTimer);
	m_clientUpdateTimer.data = this;
	uv_timer_start(&m_clientUpdateTimer, uv_client_update_timer_run, (uint64_t)100, (uint64_t)100);

	this->startThread();
}

Pure_TCPClient::~Pure_TCPClient()
{
	closeClient();
	this->join();
	clearData();
}


void Pure_TCPClient::connect(const char* ip, uint32_t port, uint32_t sessionId)
{
	if (m_isStop)
		return;

	assert(ip != NULL);

	Pure_TCPClientConnectOperation* opData = (Pure_TCPClientConnectOperation*)fc_malloc(sizeof(Pure_TCPClientConnectOperation));
	new (opData)Pure_TCPClientConnectOperation();

	opData->ip = ip;
	opData->port = port;
	opData->sessionID = sessionId;
	pushOperation(Pure_TCP_CLI_OP_CONNECT, opData, 0U, 0U);
}

void Pure_TCPClient::closeClient()
{
	if (m_isStop)
		return;
	m_isStop = true;
	pushOperation(Pure_TCP_CLI_OP_CLIENT_CLOSE, NULL, 0U, 0U);
}

void Pure_TCPClient::updateFrame()
{
	if (m_msgMutex.trylock() != 0)
	{
		return;
	}

	if (m_msgQue.empty())
	{
		m_msgMutex.unlock();
		return;
	}

	while (!m_msgQue.empty())
	{
		m_msgDispatchQue.push(m_msgQue.front());
		m_msgQue.pop();
	}
	m_msgMutex.unlock();

	bool closeClientTag = false;
	while (!m_msgDispatchQue.empty())
	{
		const NetThreadMsg& Msg = m_msgDispatchQue.front();
		switch (Msg.msgType)
		{
		case NetThreadMsgType::RECV_DATA:
		{
			m_recvCall(this, Msg.pSession, Msg.data, Msg.dataLen);
			fc_free(Msg.data);
		}break;
		case NetThreadMsgType::CONNECT_FAIL:
		{
			if (m_connectCall != nullptr)
			{
				m_connectCall(this, Msg.pSession, 0);
			}
		}break;
		case NetThreadMsgType::CONNECT:
		{
			if (m_connectCall != nullptr)
			{
				m_connectCall(this, Msg.pSession, 1);
			}
		}break;
		case NetThreadMsgType::CONNECT_TIMOUT:
		{
			if (m_connectCall != nullptr)
			{
				m_connectCall(this, Msg.pSession, 2);
			}
		}break;
		case NetThreadMsgType::DIS_CONNECT:
		{
			if (m_disconnectCall != nullptr)
			{
				m_disconnectCall(this, Msg.pSession);
			}
		}break;
		case NetThreadMsgType::EXIT_LOOP:
		{
			closeClientTag = true;
		}break;
		case NetThreadMsgType::REMOVE_SESSION:
		{
			if (m_removeSessionCall != nullptr)
			{
				m_removeSessionCall(this, Msg.pSession);
			}
			pushOperation(Pure_TCP_CLI_OP_DELETE_SESSION, NULL, 0U, Msg.pSession->getSessionID());
		}break;
		default:
			break;
		}
		m_msgDispatchQue.pop();
	}
	if (closeClientTag && m_clientCloseCall != nullptr)
	{
		m_clientCloseCall(this);
	}
}

void Pure_TCPClient::removeSession(uint32_t sessionId)
{
	pushOperation(Pure_TCP_CLI_OP_REMOVE_SESSION, NULL, 0U, sessionId);
}

/// SessionManager

void Pure_TCPClient::disconnect(uint32_t sessionId)
{
	if (m_isStop)
		return;

	pushOperation(Pure_TCP_CLI_OP_DISCONNECT, NULL, 0U, sessionId);
}

void Pure_TCPClient::send(uint32_t sessionId, char* data, uint32_t len)
{
	if (m_isStop)
		return;

	if (data == 0 || len <= 0)
		return;

	char* pdata = (char*)fc_malloc(len);
	memcpy(pdata, data, len);
	pushOperation(Pure_TCP_CLI_OP_SENDDATA, pdata, len, sessionId);
}

/// TCPClient
bool Pure_TCPClient::isCloseFinish()
{
	return (m_clientStage == clientStage::STOP);
}

bool Pure_TCPClient::setSocketNoDelay(bool enable)
{
	if (m_isStop)
		return false;

	m_enableNoDelay = enable;
	pushOperation(Pure_TCP_CLI_OP_SET_NO_DELAY, NULL, 0U, 0U);
	return true;
}

bool Pure_TCPClient::setSocketKeepAlive(int32_t enable, uint32_t delay)
{
	if (m_isStop)
		return false;

	m_enableKeepAlive = enable;
	m_keepAliveDelay = delay;
	
	pushOperation(Pure_TCP_CLI_OP_SET_KEEP_ALIVE, NULL, 0U, 0U);
	return true;
}

/// Runnable
void Pure_TCPClient::run()
{
	uv_run(&m_loop, UV_RUN_DEFAULT);

	uv_loop_close(&m_loop);

	m_clientStage = clientStage::STOP;

	this->pushThreadMsg(NetThreadMsgType::EXIT_LOOP, NULL);
}

/// SessionManager
void Pure_TCPClient::executeOperation()
{
	if (m_operationMutex.trylock() != 0)
	{
		return;
	}

	if (m_operationQue.empty())
	{
		m_operationMutex.unlock();
		return;
	}

	while (!m_operationQue.empty())
	{
		m_operationDispatchQue.push(m_operationQue.front());
		m_operationQue.pop();
	}
	m_operationMutex.unlock();

	while (!m_operationDispatchQue.empty())
	{
		auto & curOperation = m_operationDispatchQue.front();
		switch (curOperation.operationType)
		{
		case Pure_TCP_CLI_OP_SENDDATA:		// 数据发送
		{
			auto sessionData = getClientSessionDataBySessionId(curOperation.sessionID);
			if (sessionData && !sessionData->removeTag)
			{
				sessionData->session->executeSend((char*)curOperation.operationData, curOperation.operationDataLen);
			}
			else
			{
				fc_free(curOperation.operationData);
			}
		}break;
		case Pure_TCP_CLI_OP_DISCONNECT:	// 断开连接
		{
			auto sessionData = getClientSessionDataBySessionId(curOperation.sessionID);
			if (sessionData->connectState == CONNECT)
			{
				sessionData->connectState = DISCONNECTING;
				sessionData->session->executeDisconnect();
			}
		}break;
		case Pure_TCP_CLI_OP_CONNECT:	// 连接
		{
			if (curOperation.operationData)
			{
				createNewConnect(curOperation.operationData);
				((Pure_TCPClientConnectOperation*)curOperation.operationData)->~Pure_TCPClientConnectOperation();
				fc_free(curOperation.operationData);
			}
		}break;
		case Pure_TCP_CLI_OP_SET_KEEP_ALIVE: //心跳设置
		{
			for (auto& it : m_allSessionMap)
			{
				auto socket = it.second->session->getTCPSocket();
				if (socket && !it.second->removeTag)
				{
					socket->setKeepAlive(m_enableKeepAlive, m_keepAliveDelay);
				}
			}
		}break;
		case Pure_TCP_CLI_OP_SET_NO_DELAY:// 设置nodelay
		{
			for (auto& it : m_allSessionMap)
			{
				auto socket = it.second->session->getTCPSocket();
				if (socket && !it.second->removeTag)
				{
					socket->setNoDelay(m_enableNoDelay);
				}
			}
		}break;
		case Pure_TCP_CLI_OP_CLIENT_CLOSE://客户端关闭
		{
			m_clientStage = clientStage::CLEAR_SESSION;
			stopSessionUpdate();
		}break;
		case Pure_TCP_CLI_OP_REMOVE_SESSION:
		{
			auto sessionData = getClientSessionDataBySessionId(curOperation.sessionID);
			if (sessionData)
			{
				if (sessionData->connectState != DISCONNECT)
				{
					sessionData->removeTag = true;
					sessionData->session->executeDisconnect();
				}
				else
				{
					if (!sessionData->removeTag)
					{
						sessionData->removeTag = true;
						pushThreadMsg(NetThreadMsgType::REMOVE_SESSION, sessionData->session);
					}
				}
			}
		}break;
		case Pure_TCP_CLI_OP_DELETE_SESSION://删除会话
		{
			auto it = m_allSessionMap.find(curOperation.sessionID);
			if (it != m_allSessionMap.end() && it->second->removeTag)
			{
				it->second->session->~Pure_TCPSession();
				fc_free(it->second->session);
				it->second->~clientSessionData();
				fc_free(it->second);
				m_allSessionMap.erase(it);
			}
		}break;
		default:
			break;
		}
		m_operationDispatchQue.pop();
	}
}

void Pure_TCPClient::onIdleRun()
{
	executeOperation();
	ThreadSleep(1);
}

void Pure_TCPClient::onSessionUpdateRun()
{}

/// TCPClient
void Pure_TCPClient::onSocketConnect(Socket* socket, int32_t status)
{
	Session* pSession = NULL;
	bool isSuc = (status == 1);

	for (auto& it : m_allSessionMap)
	{
		if (it.second->session->getTCPSocket() == socket)
		{
			pSession = it.second->session;
			it.second->session->setIsOnline(isSuc);
			it.second->connectState = isSuc ? CONNECTSTATE::CONNECT : CONNECTSTATE::DISCONNECT;

			if (isSuc)
			{
				if (m_clientStage != clientStage::START)
				{
					it.second->session->executeDisconnect();
					pSession = NULL;
				}
				else
				{
					if (it.second->removeTag)
					{
						it.second->session->executeDisconnect();
						pSession = NULL;
					}
					else
					{
						it.second->session->getTCPSocket()->setNoDelay(m_enableNoDelay);
						it.second->session->getTCPSocket()->setKeepAlive(m_enableKeepAlive, m_keepAliveDelay);
					}
				}
			}
			break;
		}
	}

	if (pSession)
	{
		if (status == 0)
		{
			pushThreadMsg(NetThreadMsgType::CONNECT_FAIL, pSession);
		}
		else if (status == 1)
		{
			pushThreadMsg(NetThreadMsgType::CONNECT, pSession);
		}
		else if (status == 2)
		{
			pushThreadMsg(NetThreadMsgType::CONNECT_TIMOUT, pSession);
		}
	}
}

void Pure_TCPClient::onSessionClose(Session* session)
{
	auto sessionData = getClientSessionDataBySession(session);
	if (sessionData)
	{
		sessionData->connectState = CONNECTSTATE::DISCONNECT;
		pushThreadMsg(NetThreadMsgType::DIS_CONNECT, sessionData->session);

		if (sessionData->removeTag)
		{
			pushThreadMsg(NetThreadMsgType::REMOVE_SESSION, sessionData->session);
		}
	}
}

void Pure_TCPClient::createNewConnect(void* data)
{
	if (data == NULL)
		return;
	Pure_TCPClientConnectOperation* opData = (Pure_TCPClientConnectOperation*)data;

	auto it = m_allSessionMap.find(opData->sessionID);
	if (it != m_allSessionMap.end())
	{
		if (it->second->removeTag)
			return;

		if (it->second->connectState == CONNECTSTATE::DISCONNECT)
		{
			if (it->second->session->executeConnect(opData->ip.c_str(), opData->port))
			{
				it->second->connectState = CONNECTSTATE::CONNECTING;
			}
			else
			{
				it->second->connectState = CONNECTSTATE::DISCONNECT;
				it->second->session->executeDisconnect();
				pushThreadMsg(NetThreadMsgType::CONNECT_FAIL, it->second->session);
			}
		}
	}
	else
	{
		TCPSocket* socket = (TCPSocket*)fc_malloc(sizeof(TCPSocket));
		new (socket) TCPSocket(&m_loop); 
		socket->setConnectCallback(std::bind(&Pure_TCPClient::onSocketConnect, this, std::placeholders::_1, std::placeholders::_2));

		Pure_TCPSession* session = Pure_TCPSession::createSession(this, socket);

		if (session == NULL)
		{
			NET_UV_LOG(NET_UV_L_FATAL, "创建会话失败，可能是内存不足!!!");
			return;
		}
		session->setSessionRecvCallback(std::bind(&Pure_TCPClient::onSessionRecvData, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
		session->setSessionClose(std::bind(&Pure_TCPClient::onSessionClose, this, std::placeholders::_1));
		session->setSessionID(opData->sessionID);
		session->setIsOnline(false);
		
		clientSessionData* cs = (clientSessionData*)fc_malloc(sizeof(clientSessionData));
		new (cs) clientSessionData();
		cs->removeTag = false;
		cs->ip = opData->ip;
		cs->port = opData->port;
		cs->session = session;
		cs->connectState = CONNECTSTATE::CONNECTING;

		m_allSessionMap.insert(std::make_pair(opData->sessionID, cs));
		
		if (socket->connect(opData->ip.c_str(), opData->port))
		{
			cs->connectState = CONNECTSTATE::CONNECTING;
		}
		else
		{
			cs->connectState = CONNECTSTATE::DISCONNECT;
			pushThreadMsg(NetThreadMsgType::CONNECT_FAIL, session);
		}
	}
}

void Pure_TCPClient::onSessionRecvData(Session* session, char* data, uint32_t len)
{
	pushThreadMsg(NetThreadMsgType::RECV_DATA, session, data, len);
}

Pure_TCPClient::clientSessionData* Pure_TCPClient::getClientSessionDataBySessionId(uint32_t sessionId)
{
	auto it = m_allSessionMap.find(sessionId);
	if (it != m_allSessionMap.end())
		return it->second;
	return NULL;
}

Pure_TCPClient::clientSessionData* Pure_TCPClient::getClientSessionDataBySession(Session* session)
{
	for (auto &it : m_allSessionMap)
	{
		if (it.second->session == session)
		{
			return it.second;
		}
	}
	return NULL;
}

void Pure_TCPClient::clearData()
{
	for (auto & it : m_allSessionMap)
	{
		it.second->session->~Pure_TCPSession();
		fc_free(it.second->session);
		it.second->~clientSessionData();
		fc_free(it.second);
	}
	m_allSessionMap.clear();

	m_msgMutex.lock();
	while (!m_msgQue.empty())
	{
		if (m_msgQue.front().data)
		{
			fc_free(m_msgQue.front().data);
		}
		m_msgQue.pop();
	}
	m_msgMutex.unlock();

	while (!m_operationQue.empty())
	{
		auto & curOperation = m_operationQue.front();
		switch (curOperation.operationType)
		{
		case Pure_TCP_CLI_OP_SENDDATA:			// 数据发送
		{
			if (curOperation.operationData)
			{
				fc_free(curOperation.operationData);
			}
		}break;
		case Pure_TCP_CLI_OP_CONNECT:			// 连接
		{
			if (curOperation.operationData)
			{
				((Pure_TCPClientConnectOperation*)curOperation.operationData)->~Pure_TCPClientConnectOperation();
				fc_free(curOperation.operationData);
			}
		}break;
		}
		m_operationQue.pop();
	}
}

void Pure_TCPClient::onClientUpdate()
{
	if (m_clientStage == clientStage::CLEAR_SESSION)
	{
		clientSessionData* data = NULL;
		for (auto& it : m_allSessionMap)
		{
			data = it.second;

			if (data->connectState == CONNECT)
			{
				data->removeTag = true;
				data->session->executeDisconnect();
			}
			else if (data->connectState == DISCONNECT)
			{
				if (!data->removeTag)
				{
					data->removeTag = true;
					pushThreadMsg(NetThreadMsgType::REMOVE_SESSION, data->session);
				}
			}
		}
		if (m_allSessionMap.empty())
		{
			m_clientStage = clientStage::WAIT_EXIT;
		}
	}
	else if (m_clientStage == clientStage::WAIT_EXIT)
	{
		stopIdle();
		uv_timer_stop(&m_clientUpdateTimer);
		uv_stop(&m_loop);
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////
void Pure_TCPClient::uv_client_update_timer_run(uv_timer_t* handle)
{
	Pure_TCPClient* c = (Pure_TCPClient*)handle->data;
	c->onClientUpdate();
}

NS_NET_UV_END
