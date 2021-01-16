#include "ProxyServer.h"
#include "ProxyConfig.h"
#include "utils/Utils.h"

ProxyServer::ProxyServer()
	: m_stopCall(nullptr)
	, m_runStatus(RUN_STATUS::STOP)
	, m_recvBuffer(NULL)
	, m_recvBufLen(0)
{
	m_sendBuffer = (uint8_t*)fc_malloc(MSG_MAX_SIZE);
}

ProxyServer::~ProxyServer()
{
	fc_free(m_sendBuffer);
	stop(NULL);
	clear();
}

bool ProxyServer::start()
{
	assert(m_runStatus == RUN_STATUS::STOP);

	auto cfg = ProxyConfig::getInstance();
	std::string encryMethod = cfg->getString("encry_method");
	std::string encryKey = cfg->getString("encry_key");
	std::string localIP = cfg->getString("svr_listenIP");
	uint32_t localPort = cfg->getUInt32("svr_listenPort");
	uint32_t listenCount = cfg->getUInt32("svr_listenCount", 0xFFFF);
	bool isipv6 = cfg->getBool("is_ipv6", false);
	bool useKcp = cfg->getBool("use_kcp", false);

	if (useKcp)
		m_pipe = std::make_unique<KCPServer>();
	else
		m_pipe = std::make_unique<TCPServer>();

	m_pipe->setCloseCallback(std::bind(&ProxyServer::on_pipeCloseCall, this, std::placeholders::_1));
	m_pipe->setNewConnectCallback(std::bind(&ProxyServer::on_pipeNewConnectCall, this, std::placeholders::_1, std::placeholders::_2));
	m_pipe->setRecvCallback(std::bind(&ProxyServer::on_pipeRecvCall, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4));
	m_pipe->setDisconnectCallback(std::bind(&ProxyServer::on_pipeDisconnectCall, this, std::placeholders::_1, std::placeholders::_2));

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

	m_dnsResolver = std::make_unique<DnsResolver>(m_loop.ptr());

	m_client = std::make_unique<TCPClient>();
	m_client->setConnectCallback(std::bind(&ProxyServer::on_ClientConnectCall, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
	m_client->setDisconnectCallback(std::bind(&ProxyServer::on_ClientDisconnectCall, this, std::placeholders::_1, std::placeholders::_2));
	m_client->setRecvCallback(std::bind(&ProxyServer::on_ClientRecvCall, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4));
	m_client->setClientCloseCallback(std::bind(&ProxyServer::on_ClientCloseCall, this, std::placeholders::_1));
	m_client->setRemoveSessionCallback(std::bind(&ProxyServer::on_ClientRemoveSessionCall, this, std::placeholders::_1, std::placeholders::_2));

	m_runStatus = RUN_STATUS::RUN;

	m_clsTimer.start(m_loop.ptr(), [](uv_timer_t* handle) {
		ProxyServer* self = (ProxyServer*)handle->data;
		self->clsLogic();
	}, 1000, 1000, this);

	m_update.start(m_loop.ptr(), [](uv_timer_t* handle) {
		ProxyServer* self =(ProxyServer*)handle->data;
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

void ProxyServer::stop(const std::function<void()>& stopCall)
{	
	m_stopCall = stopCall;
	if(m_runStatus == RUN_STATUS::RUN)
	{
		m_runStatus = RUN_STATUS::STOP_ING;
		m_client->closeClient();
		m_pipe->stopServer();
	}
}

void ProxyServer::updateFrame()
{
	m_client->updateFrame();
	m_pipe->updateFrame();
	if (m_runStatus == RUN_STATUS::STOP_ING)
	{
		if (m_client->isCloseFinish() && m_pipe->isCloseFinish())
		{
			clear();
			m_update.stop();
			m_clsTimer.stop();
		}
	}
}

void ProxyServer::clsLogic()
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

void ProxyServer::on_ClientConnectCall(Client* client, Session* session, int32_t status)
{
	//printf("connect to %s %s\n", session->getIp().c_str(), status == 1 ? "true" : "false");

	MsgHelper::initMsg(&m_sendMsg, PIPEMSG_TYPE::S2C_RESPONSE);

	if(status == 0)
		m_sendMsg.s2c_response.CODE = S2C_RESPONSE_CODE::TCP_FAIL;
	else if(status == 1)
		m_sendMsg.s2c_response.CODE = S2C_RESPONSE_CODE::TCP_SUC;
	else
		m_sendMsg.s2c_response.CODE = S2C_RESPONSE_CODE::TCP_TIME_OUT;

	this->sendToPipe(session->getSessionID(), m_sendBuffer, MsgHelper::serializeMsg(&m_sendMsg, m_sendBuffer));

	MsgHelper::destroyMsg(&m_sendMsg);

	if(status != 1)
	{
		m_client->removeSession(session->getSessionID());
	}
}

void ProxyServer::on_ClientDisconnectCall(Client* client, Session* session)
{
	//printf("disconnect to %s\n", session->getIp().c_str());

	MsgHelper::initMsg(&m_sendMsg, PIPEMSG_TYPE::S2C_DISCONNECT);
	this->sendToPipe(session->getSessionID(), m_sendBuffer, MsgHelper::serializeMsg(&m_sendMsg, m_sendBuffer));
	MsgHelper::destroyMsg(&m_sendMsg);

	m_client->removeSession(session->getSessionID());
}

void ProxyServer::on_ClientRecvCall(Client* client, Session* session, char* data, uint32_t len)
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

	MsgHelper::initMsg(&m_sendMsg, PIPEMSG_TYPE::SEND_TCP_DATA);

	m_sendMsg.common_tcp_data.METHOD = m_cypher->getMethod();
	m_sendMsg.common_tcp_data.DATA = (uint8_t*)encodeData;
	m_sendMsg.common_tcp_data.LEN = encodeLen;

	this->sendToPipe(session->getSessionID(), m_sendBuffer, MsgHelper::serializeMsg(&m_sendMsg, m_sendBuffer));

	m_sendMsg.common_tcp_data.DATA = NULL;
	MsgHelper::destroyMsg(&m_sendMsg);
}

void ProxyServer::on_ClientCloseCall(Client* client)
{}

void ProxyServer::on_ClientRemoveSessionCall(Client* client, Session* session)
{}

/// pipe
void ProxyServer::on_pipeCloseCall(Server* svr)
{}

void ProxyServer::on_pipeNewConnectCall(Server* svr, Session* session)
{
	auto pbuf = (Buffer*)fc_malloc(sizeof(Buffer));
	new(pbuf) Buffer(RECV_BUFFER_BLOCK_SIZE);

	SessionData data;
	data.buf = pbuf;
	data.timestamp = uv_now(m_loop.ptr());
	data.udp = NULL;
	m_sessionDataMap[session->getSessionID()] = data;
}

void ProxyServer::on_pipeRecvCall(Server* svr, Session* session, char* data, uint32_t len)
{
	auto it = m_sessionDataMap.find(session->getSessionID());
	if (it == m_sessionDataMap.end())
	{
		goto error_disconnect;
	}

	it->second.timestamp = uv_now(m_loop.ptr());

	auto recvBuf = it->second.buf;
	recvBuf->add(data, len);

	while (recvBuf->getDataLength() > 0)
	{
		if (MsgHelper::checkServerMsg((uint8_t*)recvBuf->getHeadBlockData()) == false)
			goto error_disconnect;

		uint32_t totalLen = recvBuf->getDataLength();
		uint32_t headSize = totalLen;
		if (headSize > recvBuf->getBlockSize())
			headSize = recvBuf->getBlockSize();

		MsgHelper::initMsg(&m_recvMsg, PIPEMSG_TYPE::INVALID);
		int32_t msgLen = MsgHelper::deserializeMsg((uint8_t*)recvBuf->getHeadBlockData(), headSize, &m_recvMsg);
		// invalid msg
		if (msgLen < 0)
		{
			goto error_disconnect;
		}
		// wait msg
		else if (msgLen == 0)
		{
			if (headSize < totalLen)
			{
				resizeRecvBuffer(totalLen);
				recvBuf->pop(m_recvBuffer, totalLen);

				MsgHelper::initMsg(&m_recvMsg, PIPEMSG_TYPE::INVALID);
				msgLen = MsgHelper::deserializeMsg((uint8_t*)m_recvBuffer, totalLen, &m_recvMsg);
				// invalid msg
				if (msgLen < 0)
					goto error_disconnect;
				// wait msg
				else if (msgLen == 0)
				{
					recvBuf->add(m_recvBuffer, totalLen);
					break;
				}
				else
				{
					this->on_pipeRecvMsg(session, m_recvMsg);
					if (totalLen > msgLen)
						recvBuf->add(m_recvBuffer + msgLen, totalLen - msgLen);
				}
			}
			else
			{
				break;
			}
		}
		else
		{
			this->on_pipeRecvMsg(session, m_recvMsg);
			recvBuf->pop(NULL, msgLen);
		}
		MsgHelper::destroyMsg(&m_recvMsg);
	}
	return;

error_disconnect:
	m_client->disconnect(session->getSessionID());
	m_pipe->disconnect(session->getSessionID());
}

void ProxyServer::on_pipeDisconnectCall(Server* svr, Session* session)
{
	m_client->disconnect(session->getSessionID());
	removeSessionData(session->getSessionID());
}


void ProxyServer::on_pipeRecvMsg(Session* session, PipeMsg& msg)
{
	switch (msg.type)
	{
	case C2S_REQUEST:
	{
		if (msg.c2s_request.CMD == SOKS5_CMD_UDP)
		{
			auto udp = (UDPSocket*)fc_malloc(sizeof(UDPSocket));
			new(udp) UDPSocket(m_loop.ptr());
			if (udp->bind("0.0.0.0", 0) == false || udp->listen(0) == false)
			{
				udp->~UDPSocket();
				fc_free(udp);

				MsgHelper::initMsg(&m_sendMsg, PIPEMSG_TYPE::S2C_RESPONSE);

				m_sendMsg.s2c_response.CODE = S2C_RESPONSE_CODE::UDP_FAIL;
				this->sendToPipe(session->getSessionID(), m_sendBuffer, MsgHelper::serializeMsg(&m_sendMsg, m_sendBuffer));

				MsgHelper::destroyMsg(&m_sendMsg);
				return;
			}

			auto sessionID = session->getSessionID();
			udp->setReadCallback([=](uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags)
			{
				do 
				{
					std::string strIP;
					uint32_t port;
					if(net_getsockAddrIPAndPort(addr, strIP, port) <= 0)
						break;

					uint32_t encodeDataLen;
					char* encodeData = m_cypher->encode(buf->base, nread, encodeDataLen);
					if (encodeData == NULL)
						break;

					MsgHelper::initMsg(&m_sendMsg, PIPEMSG_TYPE::S2C_UDP_DATA);

					m_sendMsg.common_udp_data.METHOD = m_cypher->getMethod();
					m_sendMsg.common_udp_data.DATA = (uint8_t*)encodeData;
					m_sendMsg.common_udp_data.LEN = encodeDataLen;
					m_sendMsg.common_udp_data.ADDR.PORT = port;
					m_sendMsg.common_udp_data.ADDR.ATYP = addr->sa_family == AF_INET6 ? SOKS5_ATYP_IPV6 : SOKS5_ATYP_IPV4;
					strcpy(m_sendMsg.common_udp_data.ADDR.ADDR, strIP.c_str());

					this->sendToPipe(sessionID, m_sendBuffer, MsgHelper::serializeMsg(&m_sendMsg, m_sendBuffer));

					m_sendMsg.common_udp_data.DATA = NULL;
					MsgHelper::destroyMsg(&m_sendMsg);

					return;
				} while (0);
				m_pipe->disconnect(sessionID);
				m_client->disconnect(sessionID);
			});

			m_sessionDataMap[session->getSessionID()].udp = udp;

			MsgHelper::initMsg(&m_sendMsg, PIPEMSG_TYPE::S2C_RESPONSE);

			m_sendMsg.s2c_response.CODE = S2C_RESPONSE_CODE::UDP_SUC;
			this->sendToPipe(session->getSessionID(), m_sendBuffer, MsgHelper::serializeMsg(&m_sendMsg, m_sendBuffer));

			MsgHelper::destroyMsg(&m_sendMsg);
		}
		else
		{
			if (msg.c2s_request.ADDR.ATYP == SOKS5_ATYP_DOMAIN)
			{
				auto port = msg.c2s_request.ADDR.PORT;
				auto sessionID = session->getSessionID();
				m_dnsResolver->resolve(msg.c2s_request.ADDR.ADDR, [=](const char* ipaddr) 
				{
					if (ipaddr == NULL || strlen(ipaddr) <= 0)
					{
						MsgHelper::initMsg(&m_sendMsg, PIPEMSG_TYPE::S2C_RESPONSE);
						m_sendMsg.s2c_response.CODE = S2C_RESPONSE_CODE::TCP_FAIL;
						this->sendToPipe(session->getSessionID(), m_sendBuffer, MsgHelper::serializeMsg(&m_sendMsg, m_sendBuffer));

						MsgHelper::destroyMsg(&m_sendMsg);
						return;
					}
					m_client->connect(ipaddr, port, sessionID);
				});
			}
			else
			{
				m_client->connect(msg.c2s_request.ADDR.ADDR, msg.c2s_request.ADDR.PORT, session->getSessionID());
			}
		}
	}break;
	case SEND_TCP_DATA:
	{
		uint32_t rawLen;
		char* rawData = m_cypher->decode((EncryMethod)msg.common_tcp_data.METHOD, (char*)msg.common_tcp_data.DATA, msg.common_tcp_data.LEN, rawLen);
		if (rawData == NULL)
			goto error_disconnect;

		m_client->send(session->getSessionID(), rawData, rawLen);
	}break;
	case C2S_UDP_DATA:
	{
		auto& sessionData = m_sessionDataMap[session->getSessionID()];
		if (sessionData.udp == NULL)
			goto error_disconnect;

		uint32_t rawLen;
		char* rawData = m_cypher->decode((EncryMethod)msg.common_udp_data.METHOD, (char*)msg.common_udp_data.DATA, msg.common_udp_data.LEN, rawLen);
		if (rawData == NULL)
			goto error_disconnect;
		
		uint32_t addr_len = 0;
		struct sockaddr* addr = net_getsocketAddr(msg.common_udp_data.ADDR.ADDR, msg.common_udp_data.ADDR.PORT, &addr_len);
		if (addr == NULL)
		{
			MsgHelper::initMsg(&m_sendMsg, PIPEMSG_TYPE::S2C_CANNOT_RESOLVE_ADDR);
			this->sendToPipe(session->getSessionID(), m_sendBuffer, MsgHelper::serializeMsg(&m_sendMsg, m_sendBuffer));
			MsgHelper::destroyMsg(&m_sendMsg);
			return;
		}

		sessionData.udp->udpSend(rawData, rawLen, addr);
		fc_free(addr);
	}break;
	default:
		goto error_disconnect;
		break;
	}
	return;

error_disconnect:
	m_client->disconnect(session->getSessionID());
	m_pipe->disconnect(session->getSessionID());
}

void ProxyServer::clear()
{
	for(auto& it : m_sessionDataMap)
	{
		if (it.second.buf)
		{
			it.second.buf->~Buffer();
			fc_free(it.second.buf);
		}
		if (it.second.udp)
		{
			it.second.udp->~UDPSocket();
			fc_free(it.second.udp);
		}
	}
	m_sessionDataMap.clear();
	m_pipe = NULL;
	m_client = NULL;
	m_cypher = NULL;
	m_dnsResolver = NULL;
	m_runStatus = RUN_STATUS::STOP;
	if (m_recvBuffer)
	{
		fc_free(m_recvBuffer);
		m_recvBuffer = NULL;
	}
	m_recvBufLen = 0;
}

void ProxyServer::removeSessionData(uint32_t sessionID)
{
	auto it = m_sessionDataMap.find(sessionID);
	if (m_sessionDataMap.end() != it)
	{
		if (it->second.buf)
		{
			it->second.buf->~Buffer();
			fc_free(it->second.buf);
		}
		if (it->second.udp)
		{
			it->second.udp->~UDPSocket();
			fc_free(it->second.udp);
		}
		m_sessionDataMap.erase(it);
	}
}

void ProxyServer::resizeRecvBuffer(uint32_t len)
{
	if (m_recvBufLen < len)
	{
		m_recvBufLen = len;
		if (m_recvBuffer)
			fc_free(m_recvBuffer);
		m_recvBuffer = (char*)fc_malloc(len);
	}
}

void ProxyServer::sendToPipe(uint32_t sessionID, uint8_t* data, int32_t len)
{
	if (len <= 0)
	{
		assert(0);
		m_pipe->disconnect(sessionID);
		return;
	}

	do
	{
		if (len <= BLOCK_DATA_SIZE)
		{
			m_pipe->send(sessionID, (char*)data, len);
			break;
		}
		m_pipe->send(sessionID, (char*)data, BLOCK_DATA_SIZE);
		data += BLOCK_DATA_SIZE;
		len -= BLOCK_DATA_SIZE;
	} while (1);
}