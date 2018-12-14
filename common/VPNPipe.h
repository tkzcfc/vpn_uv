#pragma once

#include "net_uv/net_uv.h"
#include <memory>
#include <functional>
#include "PipeMsg.h"
#include <unordered_map>

NS_NET_UV_OPEN;

typedef KCPClient PipeClient;
typedef KCPServer PipeServer;

#define VPN_PIPE_MAX_SESSION_COUNT (10)

typedef std::function<void(char*, uint32_t)> pipeRecvCallback;
typedef std::function<void()> pipeCloseCallback;
typedef std::function<void(bool)> pipeReadyCallback;

class VPNPipe
{
public:

	enum TYPE
	{
		CLIENT,
		SERVER,
	};

	VPNPipe(TYPE type);

	~VPNPipe();

	bool start(const char* ip, uint32_t port);

	void stop();

	void send(char* data, uint32_t len);

	inline void setRecvCallback(const pipeRecvCallback& call);

	inline void setCloseCallback(const pipeCloseCallback& call);

	inline void setReadyCallback(const pipeReadyCallback& call);

	void updateFrame();

protected:

	void on_ServerCloseCall(Server* svr);

	void on_ServerNewConnectCall(Server* svr, Session* session);

	void on_ServerRecvCall(Server* svr, Session* session, char* data, uint32_t len);

	void on_ServerDisconnectCall(Server* svr, Session* session);


	void on_ClientConnectCall(Client* client, Session* session, int32_t status);
	
	void on_ClientDisconnectCall(Client* client, Session* session);
	
	void on_ClientRecvCall(Client* client, Session* session, char* data, uint32_t len);
	
	void on_ClientCloseCall(Client* client);
	
	void on_ClientRemoveSessionCall(Client* client, Session* session);

protected:

	uint32_t getWriteSessionID();

protected:

	std::unique_ptr<PipeServer> m_svr;
	std::unique_ptr<PipeClient> m_client;
	TYPE m_type;

	pipeRecvCallback m_pipeRecvCall;
	pipeCloseCallback m_pipeCloseCall;
	pipeReadyCallback m_pipeReadyCall;
	bool m_readyStatusCache;

	std::vector<uint32_t> m_connectSessionIDArr;

	// key : 消息sessionID
	// value : m_client或m_svr分配的sessionID
	std::unordered_map<uint32_t, uint32_t> m_sessionIDMap;

	uint32_t m_uniqueID;
	std::string m_ip;
	uint32_t m_port;

	bool m_isStart;

	unsigned char* m_bufferRes;
	unsigned char* m_bufferDes;
};


void VPNPipe::setRecvCallback(const pipeRecvCallback& call)
{
	m_pipeRecvCall = std::move(call);
}

void VPNPipe::setCloseCallback(const pipeCloseCallback& call)
{
	m_pipeCloseCall = std::move(call);
}

void VPNPipe::setReadyCallback(const pipeReadyCallback& call)
{
	m_pipeReadyCall = std::move(call);
}
