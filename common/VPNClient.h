#pragma once

#include "VPNPipe.h"
#include <unordered_map>
#include "Socks5Msg.h"


class VPNClient
{
public:

	VPNClient();

	~VPNClient();

	bool start(const char* localIP, uint32_t localPort, const char* remoteIP, uint32_t remotePort, const std::function<void(bool)>& readyCall);

	void updateFrame();

	void stop(const std::function<void()>& closeCall);

protected:

	void try_stop();

	/// svr
	void on_tcp_ServerCloseCall(Server* svr);

	void on_tcp_ServerNewConnectCall(Server* svr, Session* session);
	
	void on_tcp_ServerRecvCall(Server* svr, Session* session, char* data, uint32_t len);
	
	void on_tcp_ServerDisconnectCall(Server* svr, Session* session);

	/// pipe
	void on_pipeRecvCallback(char* data, uint32_t len);
	
protected:
	std::unique_ptr<Pure_TCPServer> m_tcpSvr;
	std::unique_ptr<VPNPipe> m_pipe;
	bool m_isStart;

	struct SessionData
	{
		enum Status {
			Verification,
			Request,
			WaitRequest,
			Run,
		};
		Status status;
		S5Msg_C2S_Request request;
	};
	std::unordered_map<uint32_t, SessionData> m_sessionDataMap;


	bool m_svrStop;
	bool m_pipeStop;
	std::function<void()> m_stopCall;
};
