#pragma once


// ��־�ȼ�
#define NET_UV_L_HEART	 (0)
#define NET_UV_L_INFO	 (1)
#define NET_UV_L_WARNING (2)
#define NET_UV_L_ERROR	 (3)
#define NET_UV_L_FATAL	 (4)


#if _DEBUG 

// ��������ģʽ
#define OPEN_NET_UV_DEBUG 1
// �����ڴ���
#define OPEN_NET_MEM_CHECK 1
// log�����͵ȼ�
#define NET_UV_L_MIN_LEVEL NET_UV_L_INFO

#else

// ��������ģʽ
#define OPEN_NET_UV_DEBUG 0
// �����ڴ���
#define OPEN_NET_MEM_CHECK 0
// log�����͵ȼ�
#define NET_UV_L_MIN_LEVEL NET_UV_L_ERROR

#endif


