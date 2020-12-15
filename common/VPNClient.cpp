#include "VPNClient.h"
#include "PipeMsg.h"
#include "VPNConfig.h"
#include "Utils.h"

#define TWO_CHAR_TO_SHORT(A, I) A = (((uint8_t)data[I]) << 8) | ((uint8_t)data[(I + 1)])

VPNClient::VPNClient()
	: m_stopCall(nullptr)
	, m_runStatus(RUN_STATUS::STOP)
	, m_sendBuffer(NULL)
	, m_sendBufLen(0)
	, m_recvBuffer(NULL)
	, m_recvBufLen(0)
{}

VPNClient::~VPNClient()
{
	clear();
}

bool VPNClient::start()
{
	assert(m_runStatus == RUN_STATUS::STOP);

	std::string encryMethod = VPNConfig::getInstance()->getString("encry_method");
	std::string encryKey = VPNConfig::getInstance()->getString("encry_key");
	std::string localIP = VPNConfig::getInstance()->getString("client_listenIP");
	std::string remoteIP = VPNConfig::getInstance()->getString("remoteIP");
	uint32_t localPort = VPNConfig::getInstance()->getUInt32("client_listenPort");
	uint32_t remotePort = VPNConfig::getInstance()->getUInt32("svr_listenPort");
	uint32_t listenCount = VPNConfig::getInstance()->getUInt32("client_listenCount", 0xFFFF);
	bool isipv6 = VPNConfig::getInstance()->getBool("is_ipv6", false);
	bool useKcp = VPNConfig::getInstance()->getBool("use_kcp", false);

	m_username = VPNConfig::getInstance()->getString("username");
	m_password = VPNConfig::getInstance()->getString("password");

	if(encryMethod == "RC4" && encryKey.empty())
		return false;

	if(localPort == 0 || remotePort == 0 || listenCount == 0 || localIP.empty() || remoteIP.empty())
		return false;

	this->m_remoteIP = remoteIP;
	this->m_remotePort = remotePort;

	m_tcpSvr = std::make_unique<TCPServer>();
	m_tcpSvr->setCloseCallback(std::bind(&VPNClient::on_tcp_ServerCloseCall, this, std::placeholders::_1));
	m_tcpSvr->setNewConnectCallback(std::bind(&VPNClient::on_tcp_ServerNewConnectCall, this, std::placeholders::_1, std::placeholders::_2));
	m_tcpSvr->setRecvCallback(std::bind(&VPNClient::on_tcp_ServerRecvCall, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4));
	m_tcpSvr->setDisconnectCallback(std::bind(&VPNClient::on_tcp_ServerDisconnectCall, this, std::placeholders::_1, std::placeholders::_2));

	if (!m_tcpSvr->startServer(localIP.c_str(), localPort, isipv6, listenCount))
	{
		m_tcpSvr = NULL;
		return false;
	}

	if(encryMethod == "RC4")
		m_cypher = std::make_unique<Cypher>(EncryMethod::RC4, encryKey.c_str(), encryKey.size());
	else if(encryMethod == "SNAPPY")
		m_cypher = std::make_unique<Cypher>(EncryMethod::SNAPPY, encryKey.c_str(), encryKey.size());
	else
		m_cypher = std::make_unique<Cypher>(EncryMethod::NONE, encryKey.c_str(), encryKey.size());

	if(useKcp)
		m_pipe = std::make_unique<KCPClient>();
	else
		m_pipe = std::make_unique<TCPClient>();

	m_pipe->setClientCloseCallback([=](Client*){});
	m_pipe->setConnectCallback(std::bind(&VPNClient::on_pipeConnectCallback, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
	m_pipe->setDisconnectCallback(std::bind(&VPNClient::on_pipeDisconnectCallback, this, std::placeholders::_1, std::placeholders::_2));
	m_pipe->setRecvCallback(std::bind(&VPNClient::on_pipeRecvCallback, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4));
	m_pipe->setRemoveSessionCallback([](Client*, Session* session) {});

	m_runStatus = RUN_STATUS::RUN;

	m_update.start(m_loop.ptr(), [](uv_timer_t* handle) 
	{
		auto self = (VPNClient*)handle->data;
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

void VPNClient::stop(const std::function<void()>& closeCall)
{
	m_stopCall = closeCall;
	if(m_runStatus == RUN_STATUS::RUN)
	{
		m_runStatus = RUN_STATUS::STOP_ING;
		m_pipe->closeClient();
		m_tcpSvr->stopServer();
	}
}

void VPNClient::updateFrame()
{
	if(m_runStatus == RUN_STATUS::RUN)
	{
		m_tcpSvr->updateFrame();
		m_pipe->updateFrame();
	}
	else if(m_runStatus = RUN_STATUS::STOP_ING)
	{
		m_tcpSvr->updateFrame();
		m_pipe->updateFrame();

		if(m_tcpSvr->isCloseFinish() && m_pipe->isCloseFinish())
		{
			clear();
			m_update.stop();
		}
	}
}

/// svr
void VPNClient::on_tcp_ServerCloseCall(Server* svr)
{}

void VPNClient::on_tcp_ServerNewConnectCall(Server* svr, Session* session)
{
	SessionData data;
	memset(&data, 0, sizeof(data));
	data.status = SessionData::Verification;
	m_sessionDataMap[session->getSessionID()] = data;
}

void VPNClient::on_tcp_ServerRecvCall(Server* svr, Session* session, char* data, uint32_t len)
{
	auto it = m_sessionDataMap.find(session->getSessionID());
	if (it == m_sessionDataMap.end())
	{
		session->disconnect();
		assert(0);
		return;
	}
	
	switch (it->second.status)
	{
	case SessionData::Verification:
	{
		if (len >= 3)
		{
			S5Msg_C2S_Verification ver_data;
			memset(&ver_data, 0, sizeof(ver_data));
			ver_data.VER = data[0];
			ver_data.NMETHODS = data[1];

			for (int32_t i = 0; i < ver_data.NMETHODS; ++i)
				ver_data.METHODS[i] = data[i + 2];
			
			// 只支持socks5
			if (ver_data.VER != SOKS5_VERSION)
			{
				S5Msg_S2C_Verification ver_ret;
				ver_ret.VER = SOKS5_VERSION;
				ver_ret.METHOD = 0xff;
				session->send((char*)&ver_ret, sizeof(ver_ret));
				printf("no support socket%d\n", ver_data.VER);
			}
			else
			{
				for (int32_t i = 0; i < ver_data.NMETHODS; ++i)
				{
					if (ver_data.METHODS[i] == 0x0)
					{
						if (m_username.empty() && m_password.empty())
						{
							S5Msg_S2C_Verification ver_ret;
							ver_ret.VER = SOKS5_VERSION;
							ver_ret.METHOD = 0x00;
							session->send((char*)&ver_ret, sizeof(ver_ret));
							it->second.status = SessionData::Request;
							return;
						}
					}
					else if (ver_data.METHODS[i] == 0x02)
					{
						S5Msg_S2C_Verification ver_ret;
						ver_ret.VER = SOKS5_VERSION;
						ver_ret.METHOD = 0x02;
						session->send((char*)&ver_ret, sizeof(ver_ret));
						it->second.status = SessionData::WaitLogin;
						return;
					}
				}
				S5Msg_S2C_Verification ver_ret;
				ver_ret.VER = SOKS5_VERSION;
				ver_ret.METHOD = 0xff;
				session->send((char*)&ver_ret, sizeof(ver_ret));
			}
		}
		else
		{
			// 非法消息
			S5Msg_S2C_Verification ver_ret;
			ver_ret.VER = SOKS5_VERSION;
			ver_ret.METHOD = 0xff;
			session->send((char*)&ver_ret, sizeof(ver_ret));
		}
	}break;
	case SessionData::WaitLogin:
	{
		bool valid = false;
		do 
		{
			if (len < 4)
				break;

			uint8_t ulen = (uint8_t)data[1];
			uint8_t plen = (uint8_t)data[2 + ulen];

			if (ulen == 0)
				break;
			if(ulen + plen + 3 != len)
				break;

			if (m_username.empty() && m_password.empty())
			{
				valid = true;
				break;
			}

			if(ulen != m_username.size() || memcmp(data + 2, m_username.c_str(), ulen) != 0)
				break;

			if(plen != m_password.size())
				break;

			if(plen > 0 && memcmp(data + 3 + ulen, m_password.c_str(), plen) != 0)
				break;

			valid = true;
		} while (0);

		if (valid)
		{
			S5Msg_S2C_Password ver_ret;
			ver_ret.VER = data[0];
			ver_ret.RET = 0x00;
			session->send((char*)&ver_ret, sizeof(ver_ret));
			it->second.status = SessionData::Request;
		}
		else
		{
			S5Msg_S2C_Password ver_ret;
			ver_ret.VER = data[0];
			ver_ret.RET = 0x01;
			session->send((char*)&ver_ret, sizeof(ver_ret));
		}
	}break;
	case SessionData::Request:
	{
		if (len < 8)
		{
			session->disconnect();
			return;
		}

		bool validRequest = true;

		// version
		if (data[0] != SOKS5_VERSION)
			validRequest = false;

		// CONNECT & BIND
		if (data[1] != SOKS5_CMD_CONNECT && data[1] != SOKS5_CMD_UDP)
			validRequest = false;

		// assert(data[2] == 0)
		if (data[2] != 0x0)
			validRequest = false;

		Utils::NetAddr netAddr;
		if (validRequest && !Utils::decodeNetAddr(data + 3, len - 3, netAddr))
			validRequest = false;

		if (validRequest)
		{
			S5Msg_C2S_Request req_data;
			memset(&req_data, 0, sizeof(req_data));

			req_data.VER = data[0];
			req_data.CMD = data[1];
			req_data.RSV = data[2];
			req_data.ATYP = data[3];
			if(req_data.CMD == SOKS5_CMD_UDP)
				memcpy(req_data.DST_ADDR, session->getIp().c_str(), session->getIp().length());
			else
				memcpy(req_data.DST_ADDR, netAddr.ADDR.c_str(), netAddr.ADDR.length());
			req_data.DST_PORT = netAddr.PORT;

			it->second.request = req_data;
			it->second.status = SessionData::WaitRequest;
			it->second.buf = new Buffer(16 * 1024);
			m_pipe->connect(m_remoteIP.c_str(), m_remotePort, session->getSessionID());
		}
		else
		{
			// S5Msg_S2C_Response
			// 0x07不支持的命令
			char buf[] = { 0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
			session->send(buf, sizeof(buf));
		}
	}break;
	case SessionData::Run_TCP:
	{
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
			if (sendLen <= BLOCK_DATA_SIZE)
			{
				m_pipe->send(session->getSessionID(), sendData, sendLen);
				break;
			}
			m_pipe->send(session->getSessionID(), sendData, BLOCK_DATA_SIZE);
			sendData += BLOCK_DATA_SIZE;
			sendLen -= BLOCK_DATA_SIZE;
		} while (1);
	}break;
	default:
		break;
	}
}

void VPNClient::on_tcp_ServerDisconnectCall(Server* svr, Session* session)
{
	m_pipe->disconnect(session->getSessionID());
	removeSessionData(session->getSessionID());
}

/// pipe
void VPNClient::on_pipeRecvCallback(Client*, Session* session, char* data, uint32_t len)
{
	auto it = m_sessionDataMap.find(session->getSessionID());
	if (m_sessionDataMap.end() == it)
	{
		goto error_disconnect;
	}
	if(it->second.buf == NULL)
	{
		assert(0);
		goto error_disconnect;
	}

	auto recvBuf = it->second.buf;
	recvBuf->add(data, len);

	while (recvBuf->getDataLength() >= sizeof(MSG_P_Base))
	{
		MSG_P_Base* msg = (MSG_P_Base*)recvBuf->getHeadBlockData();
		switch(msg->msgType)
		{
			case S2C_REQUEST:
			{
				if(recvBuf->getDataLength() < sizeof(MSG_P_S2C_Response))
					return;
				this->on_pipeRecvMsgCallback(session, recvBuf->getHeadBlockData(), sizeof(MSG_P_S2C_Response));
				recvBuf->pop(NULL, sizeof(MSG_P_S2C_Response));
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
			case S2C_DISCONNECT:
			{
				this->on_pipeRecvMsgCallback(session, recvBuf->getHeadBlockData(), sizeof(MSG_P_Base));
				recvBuf->pop(NULL, sizeof(MSG_P_Base));
			}break;
			case S2C_UDP_DATA:
			{
				if (recvBuf->getDataLength() < sizeof(MSG_P_S2C_UDP_Data))
					return;

				MSG_P_S2C_UDP_Data* dataMsg = (MSG_P_S2C_UDP_Data*)msg;

				if (dataMsg->len > MSG_MAX_SIZE || dataMsg->len <= sizeof(MSG_P_S2C_UDP_Data))
					goto error_disconnect;

				if (dataMsg->method <= EncryMethod::BEGIN || dataMsg->method >= EncryMethod::END)
					goto error_disconnect;

				if (recvBuf->getDataLength() < dataMsg->len)
					return;

				resizeRecvBuffer(dataMsg->len);
				recvBuf->pop(m_recvBuffer, dataMsg->len);

				dataMsg = (MSG_P_S2C_UDP_Data*)m_recvBuffer;
				this->on_pipeRecvMsgCallback(session, m_recvBuffer, dataMsg->len);
			}break;;
			case S2C_CANNOT_RESOLVE_ADDR:
			{
				this->on_pipeRecvMsgCallback(session, recvBuf->getHeadBlockData(), sizeof(MSG_P_Base));
				recvBuf->pop(NULL, sizeof(MSG_P_Base));
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
	m_tcpSvr->disconnect(session->getSessionID());
	m_pipe->disconnect(session->getSessionID());
}

void VPNClient::on_pipeRecvMsgCallback(Session* session, char* data, uint32_t len)
{
	MSG_P_Base* msg = (MSG_P_Base*)data;
	switch (msg->msgType)
	{
	case S2C_REQUEST:
	{
		MSG_P_S2C_Response* response = (MSG_P_S2C_Response*)data;
		auto it = m_sessionDataMap.find(session->getSessionID());

		if (it == m_sessionDataMap.end() || it->second.status != SessionData::WaitRequest)
			goto error_disconnect;

		// 0x01: tcp connect succeeded
		if (response->ret == 0x01)
		{
			if (it->second.request.CMD != SOKS5_CMD_CONNECT)
				goto error_disconnect;

			it->second.status = SessionData::Run_TCP;
			// S5Msg_S2C_Response
			char buf[] = { 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
			m_tcpSvr->send(it->first, buf, sizeof(buf));
		}
		// 0x00: tcp connect failed
		// 0x02: tcp connect timed out
		else if(response->ret == 0x00 || response->ret == 0x02)
		{
			// S5Msg_S2C_Response
			// 0x04主机不可达
			char buf[] = { 0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
			m_tcpSvr->send(it->first, buf, sizeof(buf));
			m_pipe->disconnect(session->getSessionID());
		}
		// 0x03: udp ok
		else if(response->ret == 0x03)
		{
			if (it->second.request.CMD != SOKS5_CMD_UDP)
				goto error_disconnect;

			if(uv_ip4_addr((char*)it->second.request.DST_ADDR, it->second.request.DST_PORT, &it->second.send_addr) != 0)
			{
				goto error_disconnect;				
			}

			auto udp = new UDPSocket(m_loop.ptr());
			if (udp->bind("0.0.0.0", 0) == false || udp->listen(0) == false)
			{
				delete udp;
				goto error_disconnect;
			}

			auto sessionID = it->first;
			udp->setReadCallback([=](uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags)
			{
				uint32_t encodeLen;
				char* encodeData = m_cypher->encode(buf->base, nread, encodeLen);
				if (encodeData == NULL)
				{
					m_tcpSvr->disconnect(sessionID);
					m_pipe->disconnect(sessionID);
					return;
				}

				uint32_t sendLen = sizeof(MSG_P_C2S_UDP_Data) + encodeLen;
				resizeSendBuffer(sendLen);

				MSG_P_C2S_UDP_Data* msg = (MSG_P_C2S_UDP_Data*)m_sendBuffer;
				msg->msgType = PIPEMSG_TYPE::C2S_UDP_DATA;
				msg->len = sendLen;
				msg->method = m_cypher->getMethod();
				memcpy(msg + 1, encodeData, encodeLen);

				char* sendData = m_sendBuffer;
				do
				{
					if (sendLen <= BLOCK_DATA_SIZE)
					{
						m_pipe->send(session->getSessionID(), sendData, sendLen);
						break;
					}
					m_pipe->send(session->getSessionID(), sendData, BLOCK_DATA_SIZE);
					sendData += BLOCK_DATA_SIZE;
					sendLen -= BLOCK_DATA_SIZE;
				} while (1);
			});

			it->second.udp = udp;
			it->second.status = SessionData::Run_UDP;

			// S5Msg_S2C_Response
			char buf[] = { 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
			uint16_t port = ::htons((uint16_t)udp->getPort());
			memcpy(buf + 8, &port, 2);
			m_tcpSvr->send(it->first, buf, sizeof(buf));
		}
		// 0x04: udp fail
		else if(response->ret == 0x04)
		{
			// S5Msg_S2C_Response
			// 0x08不支持的地址类型
			char buf[] = { 0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
			m_tcpSvr->send(session->getSessionID(), buf, sizeof(buf));
		}
		else
		{
			goto error_disconnect;
		}
	}break;
	case S2C_DISCONNECT:
	{
		printf("recv S2C_DISCONNECT --->\n");
		goto error_disconnect;
	}break;
	case SEND_TCP_DATA:
	{
		MSG_P_TCP_Data* tcpMsg = (MSG_P_TCP_Data*)data;

		uint32_t rawLen;
		char* rawData = m_cypher->decode((EncryMethod)tcpMsg->method, data + sizeof(MSG_P_TCP_Data), tcpMsg->len - sizeof(MSG_P_TCP_Data), rawLen);
		if (rawData == NULL)
			goto error_disconnect;

		m_tcpSvr->send(session->getSessionID(), rawData, rawLen);
	}break;
	case S2C_UDP_DATA:
	{
		auto& sessionData = m_sessionDataMap[session->getSessionID()];
		if (sessionData.udp == NULL)
			goto error_disconnect;

		MSG_P_S2C_UDP_Data* udpMsg = (MSG_P_S2C_UDP_Data*)data;

		if (data[sizeof(MSG_P_S2C_UDP_Data)] != SOKS5_ATYP_IPV4 && data[sizeof(MSG_P_S2C_UDP_Data)] != SOKS5_ATYP_IPV6)
			goto error_disconnect;

		bool isIpv4 = data[sizeof(MSG_P_S2C_UDP_Data)] == SOKS5_ATYP_IPV4;

		uint32_t addrLen = isIpv4 ? 4 : 16;
		uint32_t headLen = sizeof(MSG_P_S2C_UDP_Data) + 1 + addrLen + 2;

		uint32_t rawLen;
		char* rawData = m_cypher->decode((EncryMethod)udpMsg->method, data + headLen, udpMsg->len - headLen, rawLen);
		if (rawData == NULL)
			goto error_disconnect;
		/*
		+----+------+------+----------+----------+----------+

		|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |

		+----+------+------+----------+----------+----------+

		| 2  |  1   |  1   | Variable |    2     | Variable |

		+----+------+------+----------+----------+----------+
		*/
		uint32_t sendLen = 4 + addrLen + 2 + rawLen;
		resizeSendBuffer(sendLen);

		memset(m_sendBuffer, 0, sendLen);
		memcpy(m_sendBuffer + 3, data + sizeof(MSG_P_S2C_UDP_Data), addrLen + 3);
		memcpy(m_sendBuffer + 4 + addrLen + 2, rawData, rawLen);
		sessionData.udp->udpSend(m_sendBuffer, sendLen, (const struct sockaddr*)&sessionData.send_addr);
	}break;
	case S2C_CANNOT_RESOLVE_ADDR:
	{
		goto error_disconnect;
	}break;
	default:
		printf("unknown msg:%d\n", msg->msgType);
		goto error_disconnect;
		break;
	}
	return;

error_disconnect:
	m_tcpSvr->disconnect(session->getSessionID());
	m_pipe->disconnect(session->getSessionID());
}

void VPNClient::on_pipeDisconnectCallback(Client*, Session* session)
{
	m_pipe->removeSession(session->getSessionID());
	m_tcpSvr->disconnect(session->getSessionID());
	removeSessionData(session->getSessionID());
}

void VPNClient::on_pipeConnectCallback(Client*, Session* session, int32_t status)
{
	auto it = m_sessionDataMap.find(session->getSessionID());
	if(m_sessionDataMap.end() == it)
	{
		m_pipe->disconnect(session->getSessionID());
	}
	else
	{
		if(status == 1)
		{
			if (it->second.status == SessionData::WaitRequest)
			{
				int32_t addrLen = strlen((char*)it->second.request.DST_ADDR);

				resizeSendBuffer(addrLen + sizeof(MSG_P_C2S_Request));

				MSG_P_C2S_Request* request = (MSG_P_C2S_Request*)m_sendBuffer;
				request->msgType = PIPEMSG_TYPE::C2S_REQUEST;
				request->CMD  = it->second.request.CMD;
				request->ATYP = it->second.request.ATYP;
				request->port = it->second.request.DST_PORT;
				request->len  = addrLen;
				memcpy(m_sendBuffer + sizeof(MSG_P_C2S_Request), it->second.request.DST_ADDR, addrLen);
				
				m_pipe->send(session->getSessionID(), m_sendBuffer, addrLen + sizeof(MSG_P_C2S_Request));

				printf("connect to : %s:%d\n", it->second.request.DST_ADDR, it->second.request.DST_PORT);
			}
			else
			{
				m_pipe->disconnect(session->getSessionID());
				assert(false);
			}
		}
		else
		{
			// S5Msg_S2C_Response
			// 0x01普通SOCKS服务器连接失败
			static char buf[] = { 0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
			m_tcpSvr->send(session->getSessionID(), buf, sizeof(buf));
		}
	}

	if(status != 1)
		m_pipe->removeSession(session->getSessionID());
}

void VPNClient::clear()
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
	m_tcpSvr = NULL;
	m_cypher = NULL;
	m_runStatus = RUN_STATUS::STOP;
	if (m_sendBuffer)
		free(m_sendBuffer);
	m_sendBufLen = 0;
	if (m_recvBuffer)
		free(m_recvBuffer);
	m_recvBufLen = 0;
}

void VPNClient::removeSessionData(uint32_t sessionID)
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

void VPNClient::resizeSendBuffer(uint32_t len)
{
	if (m_sendBufLen < len)
	{
		m_sendBufLen = len;
		if (m_sendBuffer)
			free(m_sendBuffer);
		m_sendBuffer = (char*)malloc(len);
	}
}

void VPNClient::resizeRecvBuffer(uint32_t len)
{
	if (m_recvBufLen < len)
	{
		m_recvBufLen = len;
		if (m_recvBuffer)
			free(m_recvBuffer);
		m_recvBuffer = (char*)malloc(len);
	}
}
