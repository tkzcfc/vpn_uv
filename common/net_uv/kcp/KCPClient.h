#pragma once

#include "KCPSocket.h"
#include "KCPSession.h"

NS_NET_UV_BEGIN

class KCPClient : public Client
{
protected:

	struct clientSessionData
	{
		clientSessionData() {}
		~clientSessionData() {}
		CONNECTSTATE connectState;
		bool removeTag; // �Ƿ񱻱���Ƴ�
		bool reconnect;	// �Ƿ��������
		float curtime;
		float totaltime;
		std::string ip;
		uint32_t port;
		KCPSession* session;
	};

public:

	KCPClient();
	KCPClient(const KCPClient&) = delete;
	virtual ~KCPClient();

	/// Client
	virtual void connect(const char* ip, uint32_t port, uint32_t sessionId)override;

	virtual void closeClient()override;

	virtual void updateFrame()override;

	virtual void removeSession(uint32_t sessionId)override;

	/// SessionManager
	virtual void send(uint32_t sessionId, char* data, uint32_t len)override;

	virtual void disconnect(uint32_t sessionId)override;

	//��������socket�Ƿ��Զ�����
	void setAutoReconnect(bool isAuto);

	//��������socket�Զ�����ʱ��(��λ��S)
	void setAutoReconnectTime(float time);

	//�Ƿ��Զ�����
	void setAutoReconnectBySessionID(uint32_t sessionID, bool isAuto);

	//�Զ�����ʱ��(��λ��S)
	void setAutoReconnectTimeBySessionID(uint32_t sessionID, float time);

protected:

	/// Runnable
	virtual void run()override;

	/// SessionManager
	virtual void executeOperation()override;

	/// Client
	virtual void onIdleRun()override;

	virtual void onSessionUpdateRun()override;

	/// KCPClient
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

	bool m_reconnect;		// �Ƿ��Զ���������
	float m_totalTime;		// ��������ʱ��

	// ���лỰ
	std::map<uint32_t, clientSessionData*> m_allSessionMap;

	bool m_isStop;

protected:

	static void uv_client_update_timer_run(uv_timer_t* handle);
};



NS_NET_UV_END
