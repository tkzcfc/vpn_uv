#pragma once

#include "Socks5Msg.h"
#include "net_uv.h"
#include "Cypher.h"
#include "DnsResolver.h"
#include <unordered_map>
#include <memory>

NS_NET_UV_OPEN;

class ProxyServer
{
public:
	ProxyServer();

	~ProxyServer();

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

	void on_pipeRecvMsg(Session*, PipeMsg& msg);

	void clear();

	void removeSessionData(uint32_t sessionID);
	
	void resizeRecvBuffer(uint32_t len);

	void sendToPipe(uint32_t sessionID, uint8_t* data, int32_t len);

protected:

	std::unique_ptr<TCPClient> m_client;
	std::unique_ptr<Server> m_pipe;
	std::unique_ptr<Cypher> m_cypher;
	std::unique_ptr<DnsResolver> m_dnsResolver;

	RUN_STATUS m_runStatus;
	std::function<void()> m_stopCall;
	UVLoop m_loop;
	// 逻辑定时器
	UVTimer m_update;
	// 定时清理无效连接
	UVTimer m_clsTimer;

	PipeMsg m_recvMsg;
	PipeMsg m_sendMsg;
	uint8_t* m_sendBuffer;
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

