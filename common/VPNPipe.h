#pragma once

#include "net_uv/net_uv.h"
#include <memory>
#include <functional>
#include "PipeMsg.h"
#include <unordered_map>
#include <chrono>


NS_NET_UV_OPEN;

// 最大会话数量
#define VPN_PIPE_MAX_SESSION_COUNT (0xFFFF)
// 预分配回话数量
#define VPN_PIPE_PRE_SESSION_COUNT (2)


#define USE_SNAPPY 1


#if USE_SNAPPY 
#include "snappy/snappy.h"
#else
extern"C"
{
#include "rc4.h"
}
const unsigned char rc4_key[] = "vpn_nv";
const uint32_t rc4_key_len = sizeof(rc4_key);
#endif


typedef std::function<void(char*, uint32_t)> pipeRecvCallback;
typedef std::function<void()> pipeCloseCallback;
typedef std::function<void(bool)> pipeReadyCallback;

typedef TCPClient PipeClient;
typedef TCPServer PipeServer;

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

	void addConnect();

	void onRecvData(Session*session, char* data, uint32_t len);

	void disconnectSession(uint32_t sessionID);

	uint32_t getWriteSessionID();

	uint32_t getFreeSessionCount();

	uint32_t getSessionRefCount(uint32_t sessionID);

	void eraseConnect(uint32_t msgSessionID);

	void tryDisconnectSession(uint32_t sessionID);

	void checkInvalidSession();

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
	uint32_t m_sessionCount;

	uint32_t m_checkTime;

	std::string m_ip;
	uint32_t m_port;
	bool m_isStart;

#if USE_SNAPPY 
#else
	unsigned char* m_buffer;
	struct rc4_state m_state;
#endif
	std::chrono::time_point<std::chrono::high_resolution_clock> m_lastTime;
	uint32_t m_transmittedSize;
	uint32_t m_net_uv_transmittedSize;
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
