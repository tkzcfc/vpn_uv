#pragma once

#include "Pure_TCPCommon.h"

NS_NET_UV_BEGIN


class Pure_TCPSession : public Session
{
public:
	Pure_TCPSession() = delete;
	Pure_TCPSession(const Pure_TCPSession&) = delete;
	virtual ~Pure_TCPSession();

	virtual uint32_t getPort()override;

	virtual std::string getIp()override;
	
protected:

	static Pure_TCPSession* createSession(SessionManager* sessionManager, TCPSocket* socket);

	Pure_TCPSession(SessionManager* sessionManager);

protected:

	virtual void executeSend(char* data, uint32_t len) override;

	virtual void executeDisconnect() override;

	virtual bool executeConnect(const char* ip, uint32_t port)override;

	virtual void update(uint32_t time)override;

protected:

	bool initWithSocket(TCPSocket* socket);
	
	inline TCPSocket* getTCPSocket();

protected:

	void on_socket_recv(char* data, ssize_t len);

	void on_socket_close(Socket* socket);

	friend class Pure_TCPServer;
	friend class Pure_TCPClient;

protected:	

	TCPSocket* m_socket;
};

TCPSocket* Pure_TCPSession::getTCPSocket()
{
	return m_socket;
}

NS_NET_UV_END
