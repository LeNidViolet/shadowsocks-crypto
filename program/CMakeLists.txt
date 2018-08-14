
ADD_EXECUTABLE(server-launch server.c)
TARGET_LINK_LIBRARIES(server-launch shadowsocks-crypto)

ADD_EXECUTABLE(client-launch client.c)
TARGET_LINK_LIBRARIES(client-launch shadowsocks-crypto)
