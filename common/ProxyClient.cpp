#include "ProxyClient.h"
#include "PipeMsg.h"
#include "ProxyConfig.h"
#include "utils/Utils.h"

ProxyClient::ProxyClient()
	: m_stopCall(nullptr)
	, m_runStatus(RUN_STATUS::STOP)
	, m_recvBuffer(NULL)
	, m_recvBufLen(0)
{
	m_sendBuffer = (uint8_t*)fc_malloc(MSG_MAX_SIZE);
}

ProxyClient::~ProxyClient()
{
	fc_free(m_sendBuffer);
	stop(NULL);
	clear();
}

bool ProxyClient::start()
{
	assert(m_runStatus == RUN_STATUS::STOP);

	auto cfg = ProxyConfig::getInstance();

	std::string encryMethod = cfg->getString("encry_method");
	std::string encryKey = cfg->getString("encry_key");
	std::string localIP = cfg->getString("client_listenIP");
	std::string remoteIP = cfg->getString("remoteIP");
	uint32_t localPort = cfg->getUInt32("client_listenPort");
	uint32_t remotePort = cfg->getUInt32("svr_listenPort");
	uint32_t listenCount = cfg->getUInt32("client_listenCount", 0xFFFF);
	bool isipv6 = cfg->getBool("is_ipv6", false);
	bool useKcp = cfg->getBool("use_kcp", false);

	m_username = cfg->getString("username");
	m_password = cfg->getString("password");

	if(encryMethod == "RC4" && encryKey.empty())
		return false;

	if(localPort == 0 || remotePort == 0 || listenCount == 0 || localIP.empty() || remoteIP.empty())
		return false;

	this->m_remoteIP = remoteIP;
	this->m_remotePort = remotePort;

	m_tcpSvr = std::make_unique<TCPServer>();
	m_tcpSvr->setCloseCallback(std::bind(&ProxyClient::on_tcp_ServerCloseCall, this, std::placeholders::_1));
	m_tcpSvr->setNewConnectCallback(std::bind(&ProxyClient::on_tcp_ServerNewConnectCall, this, std::placeholders::_1, std::placeholders::_2));
	m_tcpSvr->setRecvCallback(std::bind(&ProxyClient::on_tcp_ServerRecvCall, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4));
	m_tcpSvr->setDisconnectCallback(std::bind(&ProxyClient::on_tcp_ServerDisconnectCall, this, std::placeholders::_1, std::placeholders::_2));

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
	m_pipe->setConnectCallback(std::bind(&ProxyClient::on_pipeConnectCallback, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
	m_pipe->setDisconnectCallback(std::bind(&ProxyClient::on_pipeDisconnectCallback, this, std::placeholders::_1, std::placeholders::_2));
	m_pipe->setRecvCallback(std::bind(&ProxyClient::on_pipeRecvCallback, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4));
	m_pipe->setRemoveSessionCallback([](Client*, Session* session) {});

	m_runStatus = RUN_STATUS::RUN;

	m_update.start(m_loop.ptr(), [](uv_timer_t* handle) 
	{
		auto self = (ProxyClient*)handle->data;
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

void ProxyClient::stop(const std::function<void()>& closeCall)
{
	m_stopCall = closeCall;
	if(m_runStatus == RUN_STATUS::RUN)
	{
		m_runStatus = RUN_STATUS::STOP_ING;
		m_pipe->closeClient();
		m_tcpSvr->stopServer();
	}
}

void ProxyClient::updateFrame()
{
	m_tcpSvr->updateFrame();
	m_pipe->updateFrame();
	if(m_runStatus == RUN_STATUS::STOP_ING)
	{
		if(m_tcpSvr->isCloseFinish() && m_pipe->isCloseFinish())
		{
			clear();
			m_update.stop();
		}
	}
}

/// svr
void ProxyClient::on_tcp_ServerCloseCall(Server* svr)
{}

void ProxyClient::on_tcp_ServerNewConnectCall(Server* svr, Session* session)
{
	SessionData data;
	memset(&data, 0, sizeof(data));
	data.status = SessionData::Verification;
	m_sessionDataMap[session->getSessionID()] = data;
}

void ProxyClient::on_tcp_ServerRecvCall(Server* svr, Session* session, char* data, uint32_t len)
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
		// +----+----------+----------+
		// |VER | NMETHODS | METHODS  |
		// +----+----------+----------+
		// | 1  |    1     | 1 to 255 |
		// +----+----------+----------+
		if (len < 3)
		{
			S5Msg_S2C_Verification ver_ret;
			ver_ret.VER = SOKS5_VERSION;
			ver_ret.METHOD = 0xff;
			session->send((char*)&ver_ret, sizeof(ver_ret));
			return;
		}
		S5Msg_C2S_Verification ver_data;
		memset(&ver_data, 0, sizeof(ver_data));
		ver_data.VER = data[0];
		ver_data.NMETHODS = data[1];

		for (int32_t i = 0; i < ver_data.NMETHODS; ++i)
			ver_data.METHODS[i] = data[i + 2];

		if (ver_data.VER != SOKS5_VERSION)
		{
			S5Msg_S2C_Verification ver_ret;
			ver_ret.VER = SOKS5_VERSION;
			ver_ret.METHOD = 0xff;
			session->send((char*)&ver_ret, sizeof(ver_ret));
			printf("no support socket%d\n", ver_data.VER);
			return;
		}

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

		S5AddrInfo netInfo;
		if (validRequest)
		{
			auto addrLen = MsgHelper::resolvAddr(&netInfo, (uint8_t*)data + 3);
			if (addrLen != len - 3)
				validRequest = false;
		}

		if (validRequest)
		{
			S5Msg_C2S_Request req_data;
			memset(&req_data, 0, sizeof(req_data));

			req_data.VER = data[0];
			req_data.CMD = data[1];
			req_data.RSV = data[2];
			req_data.ATYP = data[3];
			if (req_data.CMD == SOKS5_CMD_UDP)
				memcpy(req_data.DST_ADDR, session->getIp().c_str(), session->getIp().length());
			else
				strcpy((char*)req_data.DST_ADDR, netInfo.ADDR);
			req_data.DST_PORT = netInfo.PORT;

			// alloc buf
			auto pbuf = (Buffer*)fc_malloc(sizeof(Buffer));
			new(pbuf) Buffer(RECV_BUFFER_BLOCK_SIZE);

			it->second.request = req_data;
			it->second.status = SessionData::WaitRequest;
			it->second.buf = pbuf;
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
		size_t encodeLen;
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
	}break;
	default:
		break;
	}
}

void ProxyClient::on_tcp_ServerDisconnectCall(Server* svr, Session* session)
{
	m_pipe->disconnect(session->getSessionID());
	removeSessionData(session->getSessionID());
}

/// pipe
void ProxyClient::on_pipeRecvCallback(Client*, Session* session, char* data, uint32_t len)
{
	auto it = m_sessionDataMap.find(session->getSessionID());
	if (m_sessionDataMap.end() == it)
	{
		m_tcpSvr->disconnect(session->getSessionID());
		m_pipe->disconnect(session->getSessionID());
		return;
	}
	if(it->second.buf == NULL)
	{
		assert(0);
		m_tcpSvr->disconnect(session->getSessionID());
		m_pipe->disconnect(session->getSessionID());
		return;
	}

	auto recvBuf = it->second.buf;
	recvBuf->add(data, len);

	while (recvBuf->getDataLength() > 0)
	{
		if(MsgHelper::checkClientMsg((uint8_t*)recvBuf->getHeadBlockData()) == false)
		{
			m_tcpSvr->disconnect(session->getSessionID());
			m_pipe->disconnect(session->getSessionID());
			return;
		}

		uint32_t totalLen = recvBuf->getDataLength();
		uint32_t headSize = totalLen;
		if (headSize > recvBuf->getHeadDataLen())
			headSize = recvBuf->getHeadDataLen();

		MsgHelper::initMsg(&m_recvMsg, PIPEMSG_TYPE::INVALID);
		int32_t msgLen = MsgHelper::deserializeMsg((uint8_t*)recvBuf->getHeadBlockData(), headSize, &m_recvMsg);
		// invalid msg
		if (msgLen < 0)
		{
			m_tcpSvr->disconnect(session->getSessionID());
			m_pipe->disconnect(session->getSessionID());
			return;
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
				{
					m_tcpSvr->disconnect(session->getSessionID());
					m_pipe->disconnect(session->getSessionID());
					return;
				}
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
}

void ProxyClient::on_pipeRecvMsg(Session* session, PipeMsg& msg)
{
	switch (msg.type)
	{
	case S2C_RESPONSE:
	{
		auto it = m_sessionDataMap.find(session->getSessionID());
		if (it == m_sessionDataMap.end() || it->second.status != SessionData::WaitRequest)
			goto error_disconnect;

		if (msg.s2c_response.CODE == S2C_RESPONSE_CODE::TCP_SUC)
		{
			if (it->second.request.CMD != SOKS5_CMD_CONNECT)
				goto error_disconnect;

			it->second.status = SessionData::Run_TCP;
			// S5Msg_S2C_Response
			char buf[] = { 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
			m_tcpSvr->send(it->first, buf, sizeof(buf));
		}
		else if (msg.s2c_response.CODE == S2C_RESPONSE_CODE::TCP_FAIL || msg.s2c_response.CODE == S2C_RESPONSE_CODE::TCP_TIME_OUT)
		{
			// S5Msg_S2C_Response
			// 0x04主机不可达
			char buf[] = { 0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
			m_tcpSvr->send(it->first, buf, sizeof(buf));
			m_pipe->disconnect(session->getSessionID());
		}
		else if (msg.s2c_response.CODE == S2C_RESPONSE_CODE::UDP_SUC)
		{
			if (it->second.request.CMD != SOKS5_CMD_UDP)
				goto error_disconnect;

			if (uv_ip4_addr((char*)it->second.request.DST_ADDR, it->second.request.DST_PORT, &it->second.send_addr) != 0)
			{
				goto error_disconnect;
			}

			auto udp = (UDPSocket*)fc_malloc(sizeof(UDPSocket));
			new(udp) UDPSocket(m_loop.ptr());
			if (udp->bind("0.0.0.0", 0) == false || udp->listen(0) == false)
			{
				udp->~UDPSocket();
				fc_free(udp);
				goto error_disconnect;
			}

			auto sessionID = it->first;
			udp->setReadCallback([=](uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags)
			{
				do
				{
					if (nread < 11)
						break;

					MsgHelper::initMsg(&m_sendMsg, PIPEMSG_TYPE::C2S_UDP_DATA);

					auto addrLen = MsgHelper::resolvAddr(&m_sendMsg.common_udp_data.ADDR, (uint8_t*)&buf->base[3]);
					if (addrLen <= 0)
						break;

					size_t encodeLen;
					char* encodeData = m_cypher->encode(buf->base + addrLen + 3, nread - addrLen - 3, encodeLen);
					if (encodeData == NULL)
						break;

					m_sendMsg.common_udp_data.METHOD = m_cypher->getMethod();
					m_sendMsg.common_udp_data.DATA = (uint8_t*)encodeData;
					m_sendMsg.common_udp_data.LEN = encodeLen;

					this->sendToPipe(session->getSessionID(), m_sendBuffer, MsgHelper::serializeMsg(&m_sendMsg, m_sendBuffer));

					m_sendMsg.common_udp_data.DATA = NULL;
					MsgHelper::destroyMsg(&m_sendMsg);
					return;
				} while (0);
				m_tcpSvr->disconnect(sessionID);
				m_pipe->disconnect(sessionID);
			});

			it->second.udp = udp;
			it->second.status = SessionData::Run_UDP;

			// S5Msg_S2C_Response
			char buf[] = { 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
			writeUint16InBigEndian(buf + 8, (uint16_t)udp->getPort());
			m_tcpSvr->send(it->first, buf, sizeof(buf));
		}
		else if (msg.s2c_response.CODE == S2C_RESPONSE_CODE::UDP_FAIL)
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
		goto error_disconnect;
	}break;
	case SEND_TCP_DATA:
	{
		size_t rawLen;
		char* rawData = m_cypher->decode((EncryMethod)msg.common_tcp_data.METHOD, (char*)msg.common_tcp_data.DATA, msg.common_tcp_data.LEN, rawLen);
		if (rawData == NULL)
			goto error_disconnect;

		m_tcpSvr->send(session->getSessionID(), rawData, rawLen);
	}break;
	case S2C_UDP_DATA:
	{
		auto& sessionData = m_sessionDataMap[session->getSessionID()];
		if (sessionData.udp == NULL)
			goto error_disconnect;

		size_t rawLen;
		char* rawData = m_cypher->decode((EncryMethod)msg.common_udp_data.METHOD, (char*)msg.common_udp_data.DATA, msg.common_udp_data.LEN, rawLen);
		if (rawData == NULL)
			goto error_disconnect;

		/*
		+----+------+------+----------+----------+----------+
		|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
		+----+------+------+----------+----------+----------+
		| 2  |  1   |  1   | Variable |    2     | Variable |
		+----+------+------+----------+----------+----------+
		*/
		m_sendBuffer[0] = 0x00;
		m_sendBuffer[1] = 0x00;
		m_sendBuffer[2] = 0x00;

		auto addrlen = MsgHelper::serializeAddr(&msg.common_udp_data.ADDR, m_sendBuffer + 3);
		if(addrlen <= 0)
			goto error_disconnect;

		memcpy(m_sendBuffer + addrlen + 3, rawData, rawLen);
		sessionData.udp->udpSend((char*)m_sendBuffer, rawLen + addrlen + 3, (const struct sockaddr*)&sessionData.send_addr);
	}break;
	case S2C_CANNOT_RESOLVE_ADDR:
	{
		goto error_disconnect;
	}break;
	default:
		goto error_disconnect;
		break;
	}

	return;
error_disconnect:
	m_tcpSvr->disconnect(session->getSessionID());
	m_pipe->disconnect(session->getSessionID());
}

void ProxyClient::on_pipeDisconnectCallback(Client*, Session* session)
{
	m_pipe->removeSession(session->getSessionID());
	m_tcpSvr->disconnect(session->getSessionID());
	removeSessionData(session->getSessionID());
}

void ProxyClient::on_pipeConnectCallback(Client*, Session* session, int32_t status)
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
				MsgHelper::initMsg(&m_sendMsg, PIPEMSG_TYPE::C2S_REQUEST);

				m_sendMsg.c2s_request.CMD = it->second.request.CMD;
				m_sendMsg.c2s_request.ADDR.PORT = it->second.request.DST_PORT;
				m_sendMsg.c2s_request.ADDR.ATYP = it->second.request.ATYP;
				strcpy(m_sendMsg.c2s_request.ADDR.ADDR, (const char*)it->second.request.DST_ADDR);

				this->sendToPipe(session->getSessionID(), m_sendBuffer, MsgHelper::serializeMsg(&m_sendMsg, m_sendBuffer));

				MsgHelper::destroyMsg(&m_sendMsg);
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

void ProxyClient::clear()
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
	m_tcpSvr = NULL;
	m_cypher = NULL;
	m_runStatus = RUN_STATUS::STOP;
	if (m_recvBuffer)
	{
		fc_free(m_recvBuffer);
		m_recvBuffer = NULL;
	}
	m_recvBufLen = 0;
}

void ProxyClient::removeSessionData(uint32_t sessionID)
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

void ProxyClient::resizeRecvBuffer(uint32_t len)
{
	if (m_recvBufLen < len)
	{
		m_recvBufLen = len;
		if (m_recvBuffer)
			fc_free(m_recvBuffer);
		m_recvBuffer = (char*)fc_malloc(len);
	}
}

void ProxyClient::sendToPipe(uint32_t sessionID, uint8_t* data, int32_t len)
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