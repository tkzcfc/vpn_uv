#pragma once

#include "Socks5Msg.h"
#include "net_uv.h"
#include "Cypher.h"
#include <unordered_map>
#include <memory>
#include <time.h>

NS_NET_UV_OPEN;

class VPNServer
{
public:
	VPNServer();

	~VPNServer();

	bool start();

	void stop(const std::function<void()>& stopCall);

protected:

	void updateFrame();

	void clsLogic();

	/// client
	void on_ClientConnectCall(Client* client, Session* session, int32_t status);

	void on_ClientDisconnectCall(Client* client, Session* session);

	void on_ClientRecvCall(Client* client, Session* session, char* data, uint32_t len);

	void on_ClientCloseCall(Client* client);

	void on_ClientRemoveSessionCall(Client* client, Session* session);

	/// pipe
	void on_pipeCloseCall(Server* svr);

	void on_pipeNewConnectCall(Server* svr, Session* session);
	
	void on_pipeRecvCall(Server* svr, Session* session, char* data, uint32_t len);
	
	void on_pipeDisconnectCall(Server* svr, Session* session);

	void on_pipeRecvMsgCallback(Session*, char* data, uint32_t len);

	void clear();

	void removeSessionData(uint32_t sessionID);

	void resizeSendBuffer(uint32_t len);

	void resizeRecvBuffer(uint32_t len);

protected:

	std::unique_ptr<TCPClient> m_client;
	std::unique_ptr<Server> m_pipe;
	std::unique_ptr<Cypher> m_cypher;

	RUN_STATUS m_runStatus;
	std::function<void()> m_stopCall;
	UVLoop m_loop;
	UVTimer m_update;
	UVTimer m_clsTimer;

	char* m_sendBuffer;
	uint32_t m_sendBufLen;
	char* m_recvBuffer;
	uint32_t m_recvBufLen;

	struct SessionData
	{
		Buffer* buf;
		UDPSocket* udp;
		uint64_t timestamp;
	};
	std::unordered_map<uint32_t, SessionData> m_sessionDataMap;
};

