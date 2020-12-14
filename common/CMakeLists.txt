project(common)

set(LIB_COMMON_SRC
  PipeMsg.h
  rc4.c
  rc4.h
  Socks5Msg.h
  Utils.cpp
  Utils.h
  Cypher.cpp
  Cypher.h
  VPNClient.cpp
  VPNClient.h
  VPNConfig.cpp
  VPNConfig.h
  VPNServer.cpp
  VPNServer.h
)

add_library(${PROJECT_NAME} STATIC ${LIB_COMMON_SRC})

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(${PROJECT_NAME} PRIVATE libuv net_uv snappy)


