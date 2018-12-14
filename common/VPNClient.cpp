#include "VPNClient.h"

VPNClient::VPNClient()
	: m_isStart(false)
	, m_svrStop(true)
	, m_pipeStop(true)
	, m_stopCall(nullptr)
{}

VPNClient::~VPNClient()
{}

bool VPNClient::start(const char* localIP, uint32_t localPort, const char* remoteIP, uint32_t remotePort, const std::function<void(bool)>& readyCall)
{
	if (m_isStart)
	{
		return false;
	}

	m_tcpSvr = std::make_unique<TCPServer>();
	m_tcpSvr->setCloseCallback(std::bind(&VPNClient::on_tcp_ServerCloseCall, this, std::placeholders::_1));
	m_tcpSvr->setNewConnectCallback(std::bind(&VPNClient::on_tcp_ServerNewConnectCall, this, std::placeholders::_1, std::placeholders::_2));
	m_tcpSvr->setRecvCallback(std::bind(&VPNClient::on_tcp_ServerRecvCall, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4));
	m_tcpSvr->setDisconnectCallback(std::bind(&VPNClient::on_tcp_ServerDisconnectCall, this, std::placeholders::_1, std::placeholders::_2));

	bool r = m_tcpSvr->startServer(localIP, localPort, false);;
	if (!r)
	{
		m_tcpSvr = NULL;
		return false;
	}
	
	m_pipe = std::make_unique<VPNPipe>(VPNPipe::TYPE::CLIENT);
	m_pipe->setRecvCallback(std::bind(&VPNClient::on_pipeRecvCallback, this, std::placeholders::_1, std::placeholders::_2));
	m_pipe->setCloseCallback([this]() 
	{
		m_pipeStop = true;
		try_stop();
	});
	m_pipe->setReadyCallback(readyCall);
	m_pipe->start(remoteIP, remotePort);

	m_pipeStop = false;
	m_svrStop = false;
	m_isStart = true;

	return true;
}

void VPNClient::stop(const std::function<void()>& closeCall)
{
	if (!m_isStart)
	{
		return;
	}
	m_isStart = false;
	m_pipe->stop();
	m_tcpSvr->stopServer();
}

void VPNClient::try_stop()
{
	if (m_svrStop && m_pipeStop)
	{
		m_pipe = NULL;
		m_tcpSvr = NULL;
		if (m_stopCall != NULL)
		{
			m_stopCall();
		}
	}
}

void VPNClient::updateFrame()
{
	if (!m_isStart)
	{
		if (m_tcpSvr != NULL)
		{
			m_tcpSvr->updateFrame();
		}
		if (m_pipe != NULL)
		{
			m_pipe->updateFrame();
		}
		return;
	}
	m_tcpSvr->updateFrame();
	m_pipe->updateFrame();
}

/// svr
void VPNClient::on_tcp_ServerCloseCall(Server* svr)
{
	m_svrStop = true;
	try_stop();
}

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
	if (it != m_sessionDataMap.end())
	{
		switch (it->second.status)
		{
		case SessionData::Verification:
		{
			printf("Verification %d\n", len);
			if (len >= 3)
			{
				S5Msg_C2S_Verification ver_data;
				memset(&ver_data, 0, sizeof(ver_data));
				ver_data.VER = data[0];
				ver_data.NMETHODS = data[1];
				for (int32_t i = 0; i < ver_data.NMETHODS; ++i)
				{
					ver_data.METHODS[i] = data[i + 2];
				}
				
				// 只支持socks5
				if (ver_data.VER != 0x5)
				{
					S5Msg_S2C_Verification ver_ret;
					ver_ret.VER = 0x5;
					ver_ret.METHOD = 0xff;
					session->send((char*)&ver_ret, sizeof(ver_ret));
				}
				else
				{
					// 只支持METHOD为不需要认证
					for (int32_t i = 0; i < ver_data.NMETHODS; ++i)
					{
						if (ver_data.METHODS[i] != 0)
						{
							S5Msg_S2C_Verification ver_ret;
							ver_ret.VER = 0x5;
							ver_ret.METHOD = 0xff;
							session->send((char*)&ver_ret, sizeof(ver_ret));
							return;
						}
					}
					// 验证成功
					S5Msg_S2C_Verification ver_ret;
					ver_ret.VER = 0x5;
					ver_ret.METHOD = 0x00;
					session->send((char*)&ver_ret, sizeof(ver_ret));
					it->second.status = SessionData::Request;
				}
			}
			else
			{
				// 非法消息
				S5Msg_S2C_Verification ver_ret;
				ver_ret.VER = 0x5;
				ver_ret.METHOD = 0xff;
				session->send((char*)&ver_ret, sizeof(ver_ret));
			}
		}break;
		case SessionData::Request:
		{
			printf("Request %d\n", len);
#define TWO_CHAR_TO_SHORT(A, I) A = (((uint8_t)data[I]) << 8) | ((uint8_t)data[(I + 1)])

			//printf("---------------\n");
			//for (int i = 0; i < len; ++i)
			//{
			//	printf("%d ", (uint8_t)data[i]);
			//}
			//printf("---------------\n");

			// 不支持BIND请求和UDP转发
			if (data[0] != 5 || data[1] == 2 || data[1] == 3 || data[2] != 0)
			{
				static char buf[] = { 0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
				session->send(buf, sizeof(buf));
				return;
			}

			S5Msg_C2S_Request req_data;
			memset(&req_data, 0, sizeof(req_data));

			req_data.VER	= data[0];
			req_data.CMD	= data[1];
			req_data.RSV	= data[2];
			req_data.ATYP	= data[3];

			// ipv4
			if (req_data.ATYP == 0x01)
			{
				sprintf((char*)req_data.DST_ADDR, "%u.%u.%u.%u", (uint8_t)data[4], (uint8_t)data[5], (uint8_t)data[6], (uint8_t)data[7]);
			}
			// domain name
			else if (req_data.ATYP == 0x03)
			{
				uint8_t addrLen = (uint8_t)data[4];
				for (uint8_t i = 0; i < addrLen; ++i)
				{
					req_data.DST_ADDR[i] = data[5 + i];
				}
			}
			// ipv6
			else if (req_data.ATYP == 0x04)
			{
				uint16_t A, B, C, D, E, F, G, H;

				TWO_CHAR_TO_SHORT(A, 4);
				TWO_CHAR_TO_SHORT(B, 6);
				TWO_CHAR_TO_SHORT(C, 8);
				TWO_CHAR_TO_SHORT(D, 10);

				TWO_CHAR_TO_SHORT(E, 12);
				TWO_CHAR_TO_SHORT(F, 14);
				TWO_CHAR_TO_SHORT(G, 16);
				TWO_CHAR_TO_SHORT(H, 18);

				sprintf((char*)req_data.DST_ADDR, "%x:%x:%x:%x:%x:%x:%x:%x", A, B, C, D, E, F, G, H);
			}
			// 非法ATYP类型
			else
			{
				static char buf[] = { 0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
				session->send(buf, sizeof(buf));
				return;
			}

			TWO_CHAR_TO_SHORT(req_data.DST_PORT, len - 2);

			it->second.request = req_data;
			it->second.status = SessionData::WaitRequest;

			MSG_P_C2S_Request p_c2s_request(session->getSessionID());
			p_c2s_request.ATYP = req_data.ATYP;
			p_c2s_request.port = req_data.DST_PORT;
			memcpy(p_c2s_request.szIP, req_data.DST_ADDR, DOMAIN_NAME_MAX_LENG);
			m_pipe->send((char*)&p_c2s_request, sizeof(p_c2s_request));

			printf("connect to : %s:%d\n", req_data.DST_ADDR, req_data.DST_PORT);

#undef TWO_CHAR_TO_SHORT
		}break;
		case SessionData::Run:
		{
			printf("send [%d]\n", len);
			char* sendData = new char[sizeof(MSG_P_Base) + len];
			((MSG_P_Base*)sendData)->sessionId = session->getSessionID();
			((MSG_P_Base*)sendData)->msgType = PIPEMSG_TYPE::C2S_SENDDATA;
			memcpy(sendData + sizeof(MSG_P_Base), data, len);
			
			m_pipe->send(sendData, sizeof(MSG_P_Base) + len);
			
			delete[]sendData;
		}break;
		default:
			break;
		}
	}
}

void VPNClient::on_tcp_ServerDisconnectCall(Server* svr, Session* session)
{
	MSG_P_Base data;
	data.msgType = PIPEMSG_TYPE::C2S_DISCONNECT;
	data.sessionId = session->getSessionID();
	m_pipe->send((char*)&data, sizeof(data));

	m_sessionDataMap.erase(session->getSessionID());
}

/// pipe
void VPNClient::on_pipeRecvCallback(char* data, uint32_t len)
{
	MSG_P_Base* msg = (MSG_P_Base*)data;
	switch (msg->msgType)
	{
	case S2C_REQUEST:
	{
		//printf("S2C_REQUEST\n");
		MSG_P_S2C_Request* requestData = (MSG_P_S2C_Request*)data;
		auto it = m_sessionDataMap.find(msg->sessionId);
		if (m_sessionDataMap.end() != it && it->second.status == SessionData::WaitRequest)
		{
			if (requestData->ret == 1)
			{
				it->second.status = SessionData::Run;
				if (it->second.request.CMD == 0x01)//tcp
				{
					static char buf[] = { 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
					////
					//static char szbuf[512];
					//memcpy(szbuf, buf, sizeof(buf));

					//// domain name
					//if (it->second.request.ATYP == 0x03)
					//{
					//}
					////ipv6
					//else if (it->second.request.ATYP == 0x04)
					//{
					//}
					//// ATYP == 0x01 ipv4
					//else
					//{
					//}
					m_tcpSvr->send(it->first, buf, sizeof(buf));
				}
			}
			else
			{
				static char buf[] = { 0x05, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
				m_tcpSvr->send(it->first, buf, sizeof(buf));
				m_tcpSvr->disconnect(it->first);
			}
		}
	}break;
	case S2C_DISCONNECT:
	{
		//printf("S2C_DISCONNECT\n");
		m_tcpSvr->disconnect(msg->sessionId);
	}break;
	case S2C_SENDDATA:
	{
		printf("recv [%d]\n", len - sizeof(MSG_P_Base));
		m_tcpSvr->send(msg->sessionId, data + sizeof(MSG_P_Base), len - sizeof(MSG_P_Base));
	}break;
	default:
		printf("未知消息ID:%d\n", msg->msgType);
		break;
	}
}
