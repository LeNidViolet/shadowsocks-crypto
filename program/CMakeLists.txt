
ADD_EXECUTABLE(sscrypto-server-launch server.c)
TARGET_LINK_LIBRARIES(sscrypto-server-launch shadowsocks-crypto)
