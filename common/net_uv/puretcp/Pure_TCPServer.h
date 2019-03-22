#pragma once


#include "Pure_TCPSession.h"

NS_NET_UV_BEGIN

class Pure_TCPServer : public Server
{
	struct serverSessionData
	{
		serverSessionData()
		{
			isInvalid = false;
			session = NULL;
		}
		Pure_TCPSession* session;
		bool isInvalid;
	};

public:

	Pure_TCPServer();
	Pure_TCPServer(const Pure_TCPServer&) = delete;

	virtual ~Pure_TCPServer();

	/// Server
	virtual bool startServer(const char* ip, uint32_t port, bool isIPV6, int32_t maxCount)override;

	virtual bool stopServer()override;

	virtual void updateFrame()override;

	/// SessionManager
	virtual void send(uint32_t sessionID, char* data, uint32_t len)override;

	virtual void disconnect(uint32_t sessionID)override;

protected:

	/// Runnable
	virtual void run()override;

	/// SessionManager
	virtual void executeOperation()override;

	/// TCPServer
	void onNewConnect(uv_stream_t* server, int32_t status);

	void onServerSocketClose(Socket* svr);
	
	void onSessionRecvData(Session* session, char* data, uint32_t len);

	/// Server
	virtual void onIdleRun()override;

	virtual void onSessionUpdateRun()override;
	
protected:

	void startFailureLogic();

	void addNewSession(Pure_TCPSession* session);

	void onSessionClose(Session* session);

	void clearData();

protected:
	bool m_start;

	TCPSocket* m_server;

	// 会话管理
	std::map<uint32_t, serverSessionData> m_allSession;

	uint32_t m_sessionID;
};



NS_NET_UV_END
