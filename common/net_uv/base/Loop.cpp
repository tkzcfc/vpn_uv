#include "Loop.h"

NS_NET_UV_BEGIN

UVLoop::UVLoop()
{
	memset(&m_data, 0, sizeof(LoopData));
	m_data.uvLoop = this;

	uv_loop_init(&m_loop);
	m_loop.data = &m_data;
}

UVLoop::~UVLoop()
{
	clearLoopData();
}

uv_loop_t* UVLoop::ptr()
{
	return &m_loop;
}

void UVLoop::run(uv_run_mode mode)
{
	uv_run(&m_loop, mode);
}

void UVLoop::stop()
{
	uv_stop(&m_loop);
}

void UVLoop::close()
{
	uv_loop_close(&m_loop);
	clearLoopData();
}

void UVLoop::clearLoopData()
{
	for (auto& it : m_freeReadBufList)
	{
		fc_free(it.base);
	}
	m_freeReadBufList.clear();
}


void UVLoop::alloc_buf(uv_buf_t* buf, size_t size)
{
	for (auto it = m_freeReadBufList.begin(); it != m_freeReadBufList.end(); ++it)
	{
		if (it->len == size)
		{
			buf->base = it->base;
			buf->len = it->len;
			m_freeReadBufList.erase(it);
			return;
		}
	}

	buf->base = (char*)fc_malloc(size);
	buf->len = size;
}

void UVLoop::free_buf(const uv_buf_t* buf)
{
	if (buf == NULL)
	{
		return;
	}

	if (m_freeReadBufList.size() > 10)
	{
		fc_free(buf->base);
		return;
	}

	m_freeReadBufList.push_back(*buf);
}




UVIdle::UVIdle()
{
	memset(&m_idle, 0, sizeof(uv_idle_t));
}

UVIdle::~UVIdle()
{
	stop();
}

uv_idle_t* UVIdle::ptr()
{
	return &m_idle;
}

void UVIdle::start(UVLoop* loop, uv_idle_cb cb, void* data) 
{
	stop();

	uv_idle_init(loop->ptr(), &m_idle);
	m_idle.data = data;

	uv_idle_start(&m_idle, cb);
}

void UVIdle::stop()
{
	if (m_idle.data)
	{
		uv_idle_stop(&m_idle);
		m_idle.data = NULL;
	}
}




UVTimer::UVTimer()
{
	memset(&m_timer, 0, sizeof(uv_timer_t));
}

UVTimer::~UVTimer()
{
	stop();
}

uv_timer_t* UVTimer::ptr()
{
	return &m_timer;
}

void UVTimer::start(UVLoop* loop, uv_timer_cb cb, uint64_t timeout, uint64_t repeat, void* data)
{
	stop();

	uv_timer_init(loop->ptr(), &m_timer);
	m_timer.data = data;

	uv_timer_start(&m_timer, cb, timeout, repeat);
}

void UVTimer::stop()
{
	if (m_timer.data)
	{
		uv_timer_stop(&m_timer);
		m_timer.data = NULL;
	}
}

NS_NET_UV_END
