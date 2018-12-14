#pragma once

#include "VPNPipe.h"
#include <unordered_map>
#include "Socks5Msg.h"

class VPNServer
{
public:
	VPNServer();

	~VPNServer();

	bool start(const char* ip, uint32_t port);

	void stop(const std::function<void()>& stopCall);

	void updateFrame();

protected:

	void tryCallStop();

	/// client
	void on_ClientConnectCall(Client* client, Session* session, int32_t status);

	void on_ClientDisconnectCall(Client* client, Session* session);

	void on_ClientRecvCall(Client* client, Session* session, char* data, uint32_t len);

	void on_ClientCloseCall(Client* client);

	void on_ClientRemoveSessionCall(Client* client, Session* session);

	/// pipe
	void on_pipeRecvCallback(char* data, uint32_t len);

protected:

	std::unique_ptr<TCPClient> m_client;
	std::unique_ptr<VPNPipe> m_pipe;
	uint32_t m_clientUniqueSessionID;

	// key : 本地客户端连接远程地址的sessionID
	// value : 客户端传输过来的sessionID
	std::unordered_map<uint32_t, uint32_t> m_sessionIDMap;

	bool m_clientStop;
	bool m_pipeStop;
	std::function<void()> m_stopCall;
};

