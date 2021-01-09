#pragma once

#include "net_uv.h"

class DnsResolver
{
public:

	DnsResolver() = delete;

	DnsResolver(uv_loop_t* loop);

	~DnsResolver();

	void resolve(const char* addr, const std::function<void(const char*)>& call);

	void clearCache();

private:
	void onDnsResolved(void*, struct addrinfo*);

	static void on_resolved(uv_getaddrinfo_t *resolver, int status, struct addrinfo *res);

private:
	uv_loop_t* m_loop;
	std::map<std::string, std::string> m_cache;
};