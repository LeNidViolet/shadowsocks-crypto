ADD_EXECUTABLE(sscrypto-test-dnscache test-dns-cache.c)
TARGET_LINK_LIBRARIES(sscrypto-test-dnscache shadowsocks-crypto)

ADD_EXECUTABLE(sscrypto-test-dnsserver test-dns-server.c)
TARGET_LINK_LIBRARIES(sscrypto-test-dnsserver shadowsocks-crypto)

ADD_EXECUTABLE(sscrypto-test-server test-server.c)
TARGET_LINK_LIBRARIES(sscrypto-test-server shadowsocks-crypto)
