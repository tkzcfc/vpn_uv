#pragma once

#include "Socks5Msg.h"
#include "net_uv.h"
#include <unordered_map>
#include <memory>
#include "Cypher.h"

NS_NET_UV_OPEN;

class VPNClient
{
public:

	VPNClient();

	~VPNClient();

	bool start();

	void stop(const std::function<void()>& closeCall);

protected:
	void updateFrame();

	/// svr
	void on_tcp_ServerCloseCall(Server* svr);

	void on_tcp_ServerNewConnectCall(Server* svr, Session* session);
	
	void on_tcp_ServerRecvCall(Server* svr, Session* session, char* data, uint32_t len);
	
	void on_tcp_ServerDisconnectCall(Server* svr, Session* session);

	/// pipe
	void on_pipeRecvCallback(Client*, Session* session, char* data, uint32_t len);

	void on_pipeRecvMsgCallback(Session*, char* data, uint32_t len);

	void on_pipeDisconnectCallback(Client*, Session* session);

	void on_pipeConnectCallback(Client*, Session* session, int32_t status);

	void clear();

	void removeSessionData(uint32_t sessionID);

	void resizeSendBuffer(uint32_t len);

	void resizeRecvBuffer(uint32_t len);
	
protected:
	std::unique_ptr<TCPServer> m_tcpSvr;
	std::unique_ptr<Client> m_pipe;
	std::unique_ptr<Cypher> m_cypher;

	RUN_STATUS m_runStatus;
	std::string m_remoteIP;
	uint32_t m_remotePort;
	std::string m_username;
	std::string m_password;

	char* m_sendBuffer;
	uint32_t m_sendBufLen;
	char* m_recvBuffer;
	uint32_t m_recvBufLen;
	
	std::function<void()> m_stopCall;
	UVLoop m_loop;
	UVTimer m_update;

	struct SessionData
	{
		enum Status {
			Verification,
			WaitLogin,
			Request,
			WaitRequest,
			Run_TCP,
			Run_UDP
		};
		Status status;
		S5Msg_C2S_Request request;
		struct sockaddr_in send_addr;
		Buffer* buf;
		UDPSocket* udp;
	};
	std::unordered_map<uint32_t, SessionData> m_sessionDataMap;
};
