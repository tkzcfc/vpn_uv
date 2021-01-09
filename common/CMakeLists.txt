project(common)

set(LIB_COMMON_SRC
  PipeMsg.cpp
  PipeMsg.h
  Socks5Msg.h
  utils/rc4.c
  utils/rc4.h
  utils/endian.c
  utils/endian.h
  utils/Utils.cpp
  utils/Utils.h
  Cypher.cpp
  Cypher.h
  ProxyClient.cpp
  ProxyClient.h
  ProxyConfig.cpp
  ProxyConfig.h
  ProxyServer.cpp
  ProxyServer.h
  DnsResolver.cpp
  DnsResolver.h
)

add_library(${PROJECT_NAME} STATIC ${LIB_COMMON_SRC})

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(${PROJECT_NAME} PRIVATE libuv net_uv snappy)


