#include "Pure_TCPSession.h"

NS_NET_UV_BEGIN

Pure_TCPSession* Pure_TCPSession::createSession(SessionManager* sessionManager, TCPSocket* socket)
{
	Pure_TCPSession* session = (Pure_TCPSession*)fc_malloc(sizeof(Pure_TCPSession));
	new(session)Pure_TCPSession(sessionManager);
	
	if (session == NULL)
	{
		socket->~TCPSocket();
		fc_free(socket);
		return NULL;
	}

	if (session->initWithSocket(socket))
	{
		return session;
	}
	else
	{
		session->~Pure_TCPSession();
		fc_free(session);
	}
	return NULL;
}

Pure_TCPSession::Pure_TCPSession(SessionManager* sessionManager)
	: Session(sessionManager)
	, m_socket(NULL)
{
	assert(sessionManager != NULL);
}

Pure_TCPSession::~Pure_TCPSession()
{
	if (m_socket)
	{
		m_socket->~TCPSocket();
		fc_free(m_socket);
		m_socket = NULL;
	}
}

bool Pure_TCPSession::initWithSocket(TCPSocket* socket)
{
	assert(socket != NULL);
	
	socket->setRecvCallback(std::bind(&Pure_TCPSession::on_socket_recv, this, std::placeholders::_1, std::placeholders::_2));
	socket->setCloseCallback(std::bind(&Pure_TCPSession::on_socket_close, this, std::placeholders::_1));

	m_socket = socket;
	return true;
}

void Pure_TCPSession::executeSend(char* data, uint32_t len)
{
	if (data == NULL || len <= 0)
		return;

	if (isOnline())
	{
		if (!m_socket->send(data, len))
		{
			executeDisconnect();
		}
	}
	else
	{
		fc_free(data);
	}
}

void Pure_TCPSession::executeDisconnect()
{
	if (isOnline())
	{
		setIsOnline(false);
		m_socket->disconnect();
	}
}

bool Pure_TCPSession::executeConnect(const char* ip, uint32_t port)
{
	return m_socket->connect(ip, port);
}

void Pure_TCPSession::on_socket_recv(char* data, ssize_t len)
{
	if (!isOnline() || len <= 0)
		return;
	char* buf = (char*)fc_malloc(sizeof(char) * len);
	memcpy(buf, data, len);
	m_sessionRecvCallback(this, buf, len);
}

void Pure_TCPSession::on_socket_close(Socket* socket)
{
	this->setIsOnline(false);
	if (m_sessionCloseCallback)
	{
		m_sessionCloseCallback(this);
	}
}

void Pure_TCPSession::update(uint32_t time)
{}

uint32_t Pure_TCPSession::getPort()
{
	return m_socket->getPort();
}

std::string Pure_TCPSession::getIp()
{
	return m_socket->getIp();
}

NS_NET_UV_END