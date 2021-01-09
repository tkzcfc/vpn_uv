#include "DnsResolver.h"

NS_NET_UV_OPEN;


struct DnsResolverData
{
	DnsResolver* self;
	std::string addr;
	std::function<void(const char*)> call;
};


DnsResolver::DnsResolver(uv_loop_t* loop)
	: m_loop(loop)
{
}

DnsResolver::~DnsResolver()
{
	this->clearCache();
}

void DnsResolver::resolve(const char* addr, const std::function<void(const char*)>& call)
{
	auto addrLen = strlen(addr);
	if (addr == NULL || addrLen <= 0 || addrLen > 256)
	{
		if (call)
			call(NULL);
	}

	assert(addr != 0);
	auto it = m_cache.find(addr);
	if (it != m_cache.end())
	{
		if (call)
			call(it->second.c_str());
		return;
	}

	struct addrinfo hints;
	hints.ai_family = PF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = 0;

	DnsResolverData* data = new DnsResolverData();
	data->self = this;
	data->addr = addr;
	data->call = call;

	uv_getaddrinfo_t* resolver = (uv_getaddrinfo_t*)fc_malloc(sizeof(uv_getaddrinfo_t));
	resolver->data = data;
	int r = uv_getaddrinfo(m_loop, resolver, on_resolved, addr, NULL, &hints);

	if (r) 
	{
		delete data;
		fc_free(resolver);
		//printf("getaddrinfo call error %s\n", uv_strerror(r));
		if (call)
			call(NULL);
	}
}

void DnsResolver::on_resolved(uv_getaddrinfo_t *resolver, int status, struct addrinfo *res)
{
	DnsResolverData* data = (DnsResolverData*)resolver->data;
	if (status < 0)
	{
		//printf("getaddrinfo callback error %s\n", uv_strerror(status));
		data->self->onDnsResolved(data, NULL);
	}
	else
		data->self->onDnsResolved(data, res);

	delete data;
	uv_freeaddrinfo(res);
	fc_free(resolver);
}

void DnsResolver::onDnsResolved(void* ud, struct addrinfo* res)
{
	DnsResolverData* data = (DnsResolverData*)ud;
	if (res && res->ai_addr)
	{
		if (res->ai_addr->sa_family == AF_INET)
		{
			char addr[17] = { '\0' };
			uv_ip4_name((struct sockaddr_in*) res->ai_addr, addr, 16);
			//printf("%s->%s\n", data->addr.c_str(), addr);

			m_cache[data->addr] = addr;
			if (data->call)
				data->call(addr);
		}
		else
		{
			char addr[47] = { '\0' };
			uv_ip6_name((struct sockaddr_in6*) res->ai_addr, addr, 46);
			//printf("%s->%s\n", data->addr.c_str(), addr);

			m_cache[data->addr] = addr;
			if (data->call)
				data->call(addr);
		}
	}
	else
	{
		if (data->call)
			data->call(NULL);
	}
}

void DnsResolver::clearCache()
{
	m_cache.clear();
}
