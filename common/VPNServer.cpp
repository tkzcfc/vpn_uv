#include "VPNServer.h"
#include "VPNConfig.h"
#include "Utils.h"

VPNServer::VPNServer()
	: m_stopCall(nullptr)
	, m_runStatus(RUN_STATUS::STOP)
	, m_sendBuffer(NULL)
	, m_sendBufLen(0)
	, m_recvBuffer(NULL)
	, m_recvBufLen(0)
{
}

VPNServer::~VPNServer()
{
	stop(NULL);
	clear();
}

bool VPNServer::start()
{
	assert(m_runStatus == RUN_STATUS::STOP);

	std::string encryMethod = VPNConfig::getInstance()->getString("encry_method");
	std::string encryKey = VPNConfig::getInstance()->getString("encry_key");
	std::string localIP = VPNConfig::getInstance()->getString("svr_listenIP");
	uint32_t localPort = VPNConfig::getInstance()->getUInt32("svr_listenPort");
	uint32_t listenCount = VPNConfig::getInstance()->getUInt32("svr_listenCount", 0xFFFF);
	bool isipv6 = VPNConfig::getInstance()->getBool("is_ipv6", false);
	bool useKcp = VPNConfig::getInstance()->getBool("use_kcp", false);

	if (useKcp)
		m_pipe = std::make_unique<KCPServer>();
	else
		m_pipe = std::make_unique<TCPServer>();

	m_pipe->setCloseCallback(std::bind(&VPNServer::on_pipeCloseCall, this, std::placeholders::_1));
	m_pipe->setNewConnectCallback(std::bind(&VPNServer::on_pipeNewConnectCall, this, std::placeholders::_1, std::placeholders::_2));
	m_pipe->setRecvCallback(std::bind(&VPNServer::on_pipeRecvCall, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4));
	m_pipe->setDisconnectCallback(std::bind(&VPNServer::on_pipeDisconnectCall, this, std::placeholders::_1, std::placeholders::_2));

	if (!m_pipe->startServer(localIP.c_str(), localPort, isipv6, listenCount))
	{
		m_pipe = NULL;
		return false;
	}

	if(encryMethod == "RC4")
		m_cypher = std::make_unique<Cypher>(EncryMethod::RC4, encryKey.c_str(), encryKey.size());
	else if(encryMethod == "SNAPPY")
		m_cypher = std::make_unique<Cypher>(EncryMethod::SNAPPY, encryKey.c_str(), encryKey.size());
	else
		m_cypher = std::make_unique<Cypher>(EncryMethod::NONE, encryKey.c_str(), encryKey.size());


	m_client = std::make_unique<TCPClient>();
	m_client->setConnectCallback(std::bind(&VPNServer::on_ClientConnectCall, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
	m_client->setDisconnectCallback(std::bind(&VPNServer::on_ClientDisconnectCall, this, std::placeholders::_1, std::placeholders::_2));
	m_client->setRecvCallback(std::bind(&VPNServer::on_ClientRecvCall, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4));
	m_client->setClientCloseCallback(std::bind(&VPNServer::on_ClientCloseCall, this, std::placeholders::_1));
	m_client->setRemoveSessionCallback(std::bind(&VPNServer::on_ClientRemoveSessionCall, this, std::placeholders::_1, std::placeholders::_2));

	m_runStatus = RUN_STATUS::RUN;

	m_clsTimer.start(m_loop.ptr(), [](uv_timer_t* handle) {
		VPNServer* self = (VPNServer*)handle->data;
		self->clsLogic();
	}, 1000, 1000, this);

	m_update.start(m_loop.ptr(), [](uv_timer_t* handle) {
		VPNServer* self =(VPNServer*)handle->data;
		self->updateFrame();
	}, 1, 1, this);

	m_loop.run(UV_RUN_DEFAULT);
	m_loop.close();

	if (m_stopCall != nullptr)
	{
		m_stopCall();
		m_stopCall = nullptr;
	}

	return true;
}

void VPNServer::stop(const std::function<void()>& stopCall)
{	
	m_stopCall = stopCall;
	if(m_runStatus == RUN_STATUS::RUN)
	{
		m_runStatus = RUN_STATUS::STOP_ING;
		m_client->closeClient();
		m_pipe->stopServer();
	}
}

void VPNServer::updateFrame()
{
	m_client->updateFrame();
	m_pipe->updateFrame();
	if (m_runStatus = RUN_STATUS::STOP_ING)
	{
		if (m_client->isCloseFinish() && m_pipe->isCloseFinish())
		{
			clear();
			m_update.stop();
			m_clsTimer.stop();
		}
	}
}

void VPNServer::clsLogic()
{
	for (auto& it : m_sessionDataMap)
	{
		if (uv_now(m_loop.ptr()) - it.second.timestamp >= 1000UL * 300UL)
		{
			m_pipe->disconnect(it.first);
			m_client->disconnect(it.first);
		}
	}
}

void VPNServer::on_ClientConnectCall(Client* client, Session* session, int32_t status)
{
	printf("connect to %s %s\n", session->getIp().c_str(), status == 1 ? "true" : "false");

	MSG_P_S2C_Response msg;
	msg.msgType = PIPEMSG_TYPE::S2C_REQUEST;
	msg.ret = status;
	m_pipe->send(session->getSessionID(), (char*)&msg, sizeof(MSG_P_S2C_Response));

	if(status != 1)
	{
		m_client->removeSession(session->getSessionID());
	}
}

void VPNServer::on_ClientDisconnectCall(Client* client, Session* session)
{
	printf("disconnect to %s\n", session->getIp().c_str());

	MSG_P_Base msg;
	msg.msgType = PIPEMSG_TYPE::S2C_DISCONNECT;
	m_pipe->send(session->getSessionID(), (char*)&msg, sizeof(MSG_P_Base));

	m_client->removeSession(session->getSessionID());
}

void VPNServer::on_ClientRecvCall(Client* client, Session* session, char* data, uint32_t len)
{
	auto it = m_sessionDataMap.find(session->getSessionID());
	if (it == m_sessionDataMap.end())
	{
		session->disconnect();
		return;
	}
	it->second.timestamp = uv_now(m_loop.ptr());

	uint32_t encodeLen;
	char* encodeData = m_cypher->encode(data, len, encodeLen);
	if (encodeData == NULL)
	{
		m_pipe->disconnect(session->getSessionID());
		session->disconnect();
		return;
	}

	uint32_t sendLen = sizeof(MSG_P_TCP_Data) + encodeLen;
	resizeSendBuffer(sendLen);

	MSG_P_TCP_Data* msg = (MSG_P_TCP_Data*)m_sendBuffer;
	msg->msgType = PIPEMSG_TYPE::SEND_TCP_DATA;
	msg->len = sendLen;
	msg->method = m_cypher->getMethod();
	memcpy(msg + 1, encodeData, encodeLen);

	char* sendData = m_sendBuffer;
	do
	{
		if(sendLen <= BLOCK_DATA_SIZE)
		{
			m_pipe->send(session->getSessionID(), sendData, sendLen);
			break;
		}
		m_pipe->send(session->getSessionID(), sendData, BLOCK_DATA_SIZE);
		sendData += BLOCK_DATA_SIZE;
		sendLen -= BLOCK_DATA_SIZE;
	}while(1);
}

void VPNServer::on_ClientCloseCall(Client* client)
{}

void VPNServer::on_ClientRemoveSessionCall(Client* client, Session* session)
{}

/// pipe
void VPNServer::on_pipeCloseCall(Server* svr)
{}

void VPNServer::on_pipeNewConnectCall(Server* svr, Session* session)
{
	SessionData data;
	data.buf = new Buffer(16 * 1024);
	data.timestamp = uv_now(m_loop.ptr());
	data.udp = NULL;
	m_sessionDataMap[session->getSessionID()] = data;
}

void VPNServer::on_pipeRecvCall(Server* svr, Session* session, char* data, uint32_t len)
{
	auto it = m_sessionDataMap.find(session->getSessionID());
	if (it == m_sessionDataMap.end())
	{
		goto error_disconnect;
	}

	it->second.timestamp = uv_now(m_loop.ptr());

	auto recvBuf = it->second.buf;
	recvBuf->add(data, len);

	while (recvBuf->getDataLength() >= sizeof(MSG_P_Base))
	{
		MSG_P_Base* msg = (MSG_P_Base*)recvBuf->getHeadBlockData();
		switch(msg->msgType)
		{
			case C2S_REQUEST:
			{
				if(recvBuf->getDataLength() < sizeof(MSG_P_C2S_Request))
					return;

				MSG_P_C2S_Request* request = (MSG_P_C2S_Request*)msg;

				if(request->CMD != SOKS5_CMD_CONNECT && request->CMD != SOKS5_CMD_UDP)
					goto error_disconnect;

				if(request->ATYP != SOKS5_ATYP_IPV4 && request->ATYP != SOKS5_ATYP_DOMAIN && request->ATYP != SOKS5_ATYP_IPV6)
					goto error_disconnect;

				if(request->port <= 0)
					goto error_disconnect;

				if(request->len <= 0 || request->len >= DOMAIN_NAME_MAX_LENG)
					goto error_disconnect;

				uint32_t totalLen = sizeof(MSG_P_C2S_Request) + request->len;
				if(recvBuf->getDataLength() < totalLen)
					return;

				resizeRecvBuffer(totalLen);
				recvBuf->pop(m_recvBuffer, totalLen);
				
				this->on_pipeRecvMsgCallback(session, m_recvBuffer, totalLen);
			}break;
			case SEND_TCP_DATA:
			{
				if(recvBuf->getDataLength() < sizeof(MSG_P_TCP_Data))
					return;
				
				MSG_P_TCP_Data* dataMsg = (MSG_P_TCP_Data*)msg;

				if (dataMsg->len > MSG_MAX_SIZE || dataMsg->len <= sizeof(MSG_P_TCP_Data))
					goto error_disconnect;

				if (dataMsg->method <= EncryMethod::BEGIN || dataMsg->method >= EncryMethod::END)
					goto error_disconnect;

				if(recvBuf->getDataLength() < dataMsg->len)
					return;

				resizeRecvBuffer(dataMsg->len);
				recvBuf->pop(m_recvBuffer, dataMsg->len);

				dataMsg = (MSG_P_TCP_Data*)m_recvBuffer;
				this->on_pipeRecvMsgCallback(session, m_recvBuffer, dataMsg->len);

			}break;
			case C2S_UDP_DATA:
			{
				if (recvBuf->getDataLength() < sizeof(MSG_P_C2S_UDP_Data))
					return;

				MSG_P_C2S_UDP_Data* dataMsg = (MSG_P_C2S_UDP_Data*)msg;

				if (dataMsg->len > MSG_MAX_SIZE || dataMsg->len <= sizeof(MSG_P_C2S_UDP_Data))
					goto error_disconnect;

				if (dataMsg->method <= EncryMethod::BEGIN || dataMsg->method >= EncryMethod::END)
					goto error_disconnect;

				if (recvBuf->getDataLength() < dataMsg->len)
					return;

				resizeRecvBuffer(dataMsg->len);
				recvBuf->pop(m_recvBuffer, dataMsg->len);

				dataMsg = (MSG_P_C2S_UDP_Data*)m_recvBuffer;
				this->on_pipeRecvMsgCallback(session, m_recvBuffer, dataMsg->len);
			}break;
			default:
			{
				printf("unknown msg:%d\n", msg->msgType);
				recvBuf->clear();
				goto error_disconnect;
			}
		}
	}
	return;

error_disconnect:
printf("error_disconnect---------- 111>\n");
	m_client->disconnect(session->getSessionID());
	m_pipe->disconnect(session->getSessionID());
}

void VPNServer::on_pipeDisconnectCall(Server* svr, Session* session)
{
	m_client->disconnect(session->getSessionID());
	removeSessionData(session->getSessionID());
}


void VPNServer::on_pipeRecvMsgCallback(Session* session, char* data, uint32_t len)
{
	MSG_P_Base* msg = (MSG_P_Base*)data;
	switch (msg->msgType)
	{
	case C2S_REQUEST:
	{
		MSG_P_C2S_Request* request = (MSG_P_C2S_Request*)data;

		if(request->len != len - sizeof(MSG_P_C2S_Request))
			goto error_disconnect;

		char szBuf[DOMAIN_NAME_MAX_LENG];
		memset(szBuf, 0, DOMAIN_NAME_MAX_LENG);
		memcpy(szBuf, data + sizeof(MSG_P_C2S_Request), request->len);

		if(request->len != strlen(szBuf))
			goto error_disconnect;

		if(request->CMD == SOKS5_CMD_UDP)
		{
			if(request->ATYP != SOKS5_ATYP_IPV4)
			{
				MSG_P_S2C_Response msg;
				msg.msgType = PIPEMSG_TYPE::S2C_REQUEST;
				msg.ret = 0x04;
				m_pipe->send(session->getSessionID(), (char*)&msg, sizeof(MSG_P_S2C_Response));
			}
			else
			{
				UDPSocket* udp = new UDPSocket(m_loop.ptr());
				if (udp->bind("0.0.0.0", 0) == false || udp->listen(0) == false)
				{
					delete udp;
					MSG_P_S2C_Response msg;
					msg.msgType = PIPEMSG_TYPE::S2C_REQUEST;
					msg.ret = 0x04;
					m_pipe->send(session->getSessionID(), (char*)&msg, sizeof(MSG_P_S2C_Response));
					return;
				}

				auto sessionID = session->getSessionID();
				udp->setReadCallback([=](uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags) 
				{
					uint32_t encodeDataLen;
					char* encodeData = m_cypher->encode(buf->base, nread, encodeDataLen);
					if (encodeData == NULL)
					{
						m_pipe->disconnect(sessionID);
						m_client->disconnect(sessionID);
						return;
					}
					struct sockaddr_in* ipv4_addr = (struct sockaddr_in*)addr;
					struct sockaddr_in6* ipv6_addr = (struct sockaddr_in6*)addr;

					bool  isIpv4 = addr->sa_family == AF_INET;

					uint32_t addrLen = isIpv4 ? sizeof(ipv4_addr->sin_addr.s_addr) : sizeof(ipv6_addr->sin6_addr);
					uint32_t msgLen = sizeof(MSG_P_S2C_UDP_Data) + 1 + addrLen + 2 + encodeDataLen;

					resizeSendBuffer(msgLen);

					MSG_P_S2C_UDP_Data* msgUdp = (MSG_P_S2C_UDP_Data*)m_sendBuffer;
					msgUdp->msgType = PIPEMSG_TYPE::S2C_UDP_DATA;
					msgUdp->len = msgLen;
					msgUdp->method = m_cypher->getMethod();
		
					m_sendBuffer[sizeof(MSG_P_S2C_UDP_Data)] = isIpv4 ? SOKS5_ATYP_IPV4 : SOKS5_ATYP_IPV6;

					if (isIpv4)
					{
						memcpy(m_sendBuffer + sizeof(MSG_P_S2C_UDP_Data) + 1, &ipv4_addr->sin_addr.s_addr, addrLen);
						memcpy(m_sendBuffer + sizeof(MSG_P_S2C_UDP_Data) + 1 + addrLen, &ipv4_addr->sin_port, 2);
					}
					else
					{
						memcpy(m_sendBuffer + sizeof(MSG_P_S2C_UDP_Data) + 1, &ipv6_addr->sin6_addr, addrLen);
						memcpy(m_sendBuffer + sizeof(MSG_P_S2C_UDP_Data) + 1 + addrLen, &ipv6_addr->sin6_port, 2);
					}
					memcpy(m_sendBuffer + sizeof(MSG_P_S2C_UDP_Data) + 1 + addrLen + 2, encodeData, encodeDataLen);
					m_pipe->send(sessionID, m_sendBuffer, msgLen);
				});

				m_sessionDataMap[session->getSessionID()].udp = udp;
				MSG_P_S2C_Response msg;
				msg.msgType = PIPEMSG_TYPE::S2C_REQUEST;
				msg.ret = 0x03;
				m_pipe->send(session->getSessionID(), (char*)&msg, sizeof(MSG_P_S2C_Response));
			}
		}
		else
		{
			m_client->connect(szBuf, request->port, session->getSessionID());
		}
	}break;
	case SEND_TCP_DATA:
	{
		MSG_P_TCP_Data* tcpMsg = (MSG_P_TCP_Data*)data;
		
		uint32_t rawLen;
		char* rawData = m_cypher->decode((EncryMethod)tcpMsg->method, data + sizeof(MSG_P_TCP_Data), tcpMsg->len - sizeof(MSG_P_TCP_Data), rawLen);
		if (rawData == NULL)
			goto error_disconnect;

		m_client->send(session->getSessionID(), rawData, rawLen);
	}break;
	case C2S_UDP_DATA:
	{
		MSG_P_C2S_UDP_Data* tcpMsg = (MSG_P_C2S_UDP_Data*)data;

		uint32_t rawLen;
		char* rawData = m_cypher->decode((EncryMethod)tcpMsg->method, data + sizeof(MSG_P_C2S_UDP_Data), tcpMsg->len - sizeof(MSG_P_C2S_UDP_Data), rawLen);
		if (rawData == NULL)
			goto error_disconnect;

		auto& sessionData = m_sessionDataMap[session->getSessionID()];
		if (sessionData.udp == NULL)
			goto error_disconnect;

		uint32_t addrLen = Utils::getNetAddrLen(rawData + 3, rawLen - 3);
		if (addrLen == 0 || addrLen >= rawLen - 3)
			goto error_disconnect;

		Utils::NetAddr netAddr;
		if (!Utils::decodeNetAddr(rawData + 3, addrLen, netAddr))
			goto error_disconnect;

		sessionData.timestamp = uv_now(m_loop.ptr());

		uint32_t addr_len = 0;
		struct sockaddr* addr = net_getsocketAddr(netAddr.ADDR.c_str(), netAddr.PORT, &addr_len);
		if (addr == NULL)
		{
			MSG_P_Base msg;
			msg.msgType = PIPEMSG_TYPE::S2C_CANNOT_RESOLVE_ADDR;
			m_pipe->send(session->getSessionID(), (char*)&msg, sizeof(MSG_P_Base));
			return;
		}

		sessionData.udp->udpSend(rawData + 3 + addrLen, rawLen - 3 - addrLen, addr);
		fc_free(addr);
	}break;
	default:
		printf("unknown msg:%d\n", msg->msgType);
		goto error_disconnect;
		break;
	}
	return;

error_disconnect:
	printf("error_disconnect---------->\n");
	m_client->disconnect(session->getSessionID());
	m_pipe->disconnect(session->getSessionID());
}

void VPNServer::clear()
{
	for(auto& it : m_sessionDataMap)
	{
		if(it.second.buf)
			delete it.second.buf;
		if (it.second.udp)
			delete it.second.udp;
	}
	m_sessionDataMap.clear();
	m_pipe = NULL;
	m_client = NULL;
	m_cypher = NULL;
	m_runStatus = RUN_STATUS::STOP;
	if (m_sendBuffer)
		free(m_sendBuffer);
	m_sendBufLen = 0;
	if (m_recvBuffer)
		free(m_recvBuffer);
	m_recvBufLen = 0;
}

void VPNServer::removeSessionData(uint32_t sessionID)
{
	auto it = m_sessionDataMap.find(sessionID);
	if (m_sessionDataMap.end() != it)
	{
		if (it->second.buf)
			delete it->second.buf;
		if (it->second.udp)
			delete it->second.udp;
		m_sessionDataMap.erase(it);
	}
}

void VPNServer::resizeSendBuffer(uint32_t len)
{
	if (m_sendBufLen < len)
	{
		m_sendBufLen = len;
		if (m_sendBuffer)
			free(m_sendBuffer);
		m_sendBuffer = (char*)malloc(len);
	}
}

void VPNServer::resizeRecvBuffer(uint32_t len)
{
	if (m_recvBufLen < len)
	{
		m_recvBufLen = len;
		if (m_recvBuffer)
			free(m_recvBuffer);
		m_recvBuffer = (char*)malloc(len);
	}
}
