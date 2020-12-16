#pragma once

#include "Socks5Msg.h"
#include "net_uv.h"
#include <unordered_map>
#include <memory>
#include "Cypher.h"

NS_NET_UV_OPEN;

class VPNClient
{
public:

	VPNClient();

	~VPNClient();

	bool start();

	void stop(const std::function<void()>& closeCall);

protected:
	void updateFrame();

	/// svr
	void on_tcp_ServerCloseCall(Server* svr);

	void on_tcp_ServerNewConnectCall(Server* svr, Session* session);
	
	void on_tcp_ServerRecvCall(Server* svr, Session* session, char* data, uint32_t len);
	
	void on_tcp_ServerDisconnectCall(Server* svr, Session* session);

	/// pipe
	void on_pipeRecvCallback(Client*, Session* session, char* data, uint32_t len);

	void on_pipeRecvMsgCallback(Session*, char* data, uint32_t len);

	void on_pipeDisconnectCallback(Client*, Session* session);

	void on_pipeConnectCallback(Client*, Session* session, int32_t status);

	void clear();

	void removeSessionData(uint32_t sessionID);

	void resizeSendBuffer(uint32_t len);

	void resizeRecvBuffer(uint32_t len);
	
protected:
	std::unique_ptr<TCPServer> m_tcpSvr;
	std::unique_ptr<Client> m_pipe;
	std::unique_ptr<Cypher> m_cypher;

	// 运行状态
	RUN_STATUS m_runStatus;

	// 远程服务器地址
	std::string m_remoteIP;
	uint32_t m_remotePort;

	// socks5用户名密码
	std::string m_username;
	std::string m_password;

	// 发送缓存buffer
	char* m_sendBuffer;
	uint32_t m_sendBufLen;
	// 接收缓存buffer
	char* m_recvBuffer;
	uint32_t m_recvBufLen;
	
	std::function<void()> m_stopCall;
	UVLoop m_loop;
	UVTimer m_update;

	struct SessionData
	{
		/*
		*
		*tcp流程:
		*		有密码模式
		*				Verification -> WaitLogin -> Request -> Run_TCP
		*		无密码模式
		*				Verification -> Request -> Run_TCP
		*
		*udp流程:
		*		有密码模式
		*				Verification -> WaitLogin -> Request -> Run_UDP
		*		无密码模式
		*				Verification -> Request -> Run_UDP
		*/
		enum Status {
			Verification,	// 等待验证,socks5客户端连接代理服务器成功
			WaitLogin,		// 等待socks5客户端发送用户名/密码进行校验
			Request,		// 等待socks5客户端发送连接信息
			WaitRequest,	// 代理服务器已经向远程服务器发送连接请求,等待远程服务器返回结果
			Run_TCP,
			Run_UDP
		};
		Status status;
		// socks5客户端请求的信息缓存
		S5Msg_C2S_Request request;
		// socks5客户端监听的udp端口
		struct sockaddr_in send_addr;
		// 接收数据缓存
		Buffer* buf;
		// 一个tcp连接只允许一个udp通道
		UDPSocket* udp;	
	};
	std::unordered_map<uint32_t, SessionData> m_sessionDataMap;
};
