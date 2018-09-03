
ADD_EXECUTABLE(sscrypto-server-launch server.c)
TARGET_LINK_LIBRARIES(sscrypto-server-launch shadowsocks-crypto)

ADD_EXECUTABLE(sscrypto-client-launch client.c)
TARGET_LINK_LIBRARIES(sscrypto-client-launch shadowsocks-crypto)
