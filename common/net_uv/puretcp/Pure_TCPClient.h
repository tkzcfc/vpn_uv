#pragma once

#include "Pure_TCPSession.h"

NS_NET_UV_BEGIN

class Pure_TCPClient : public Client
{
protected:

	struct clientSessionData
	{
		clientSessionData() {}
		~clientSessionData() {}
		CONNECTSTATE connectState;
		bool removeTag; // �Ƿ񱻱���Ƴ�
		std::string ip;
		uint32_t port;
		Pure_TCPSession* session;
	};

public:

	Pure_TCPClient();
	Pure_TCPClient(const Pure_TCPClient&) = delete;
	virtual ~Pure_TCPClient();

	/// Client
	virtual void connect(const char* ip, uint32_t port, uint32_t sessionId)override;

	virtual void closeClient()override;
	
	virtual void updateFrame()override;

	virtual void removeSession(uint32_t sessionId)override;

	/// SessionManager
	virtual void disconnect(uint32_t sessionId)override;

	virtual void send(uint32_t sessionId, char* data, uint32_t len)override;

	/// TCPClient
	bool isCloseFinish();

	//�Ƿ�����TCP_NODELAY
	bool setSocketNoDelay(bool enable);

	//��������
	bool setSocketKeepAlive(int32_t enable, uint32_t delay);

protected:

	/// Runnable
	virtual void run()override;

	/// SessionManager
	virtual void executeOperation()override;

	/// Client
	virtual void onIdleRun()override;

	virtual void onSessionUpdateRun()override;

	/// Pure_TCPClient
	void onSocketConnect(Socket* socket, int32_t status);

	void onSessionClose(Session* session);

	void onSessionRecvData(Session* session, char* data, uint32_t len);

	void createNewConnect(void* data);

	void clearData();

	clientSessionData* getClientSessionDataBySessionId(uint32_t sessionId);

	clientSessionData* getClientSessionDataBySession(Session* session);

	void onClientUpdate();

protected:
	uv_timer_t m_clientUpdateTimer;

	bool m_enableNoDelay;	
	int32_t m_enableKeepAlive; 
	uint32_t m_keepAliveDelay;

	// ���лỰ
	std::map<uint32_t, clientSessionData*> m_allSessionMap;
	
	bool m_isStop;
protected:

	static void uv_client_update_timer_run(uv_timer_t* handle);
};
NS_NET_UV_END


