CMAKE_MINIMUM_REQUIRED(VERSION 3.0)
PROJECT(shadowsocks-crypto C)

SET(CMAKE_C_STANDARD 99)

SET(SHADOWSOCKSCRYPTO_ADDTION_HDR
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
INCLUDE_DIRECTORIES(${SHADOWSOCKSCRYPTO_ADDTION_HDR})

IF(ENABLE_PROGRAMS)
    # ADD PROGRAM DIR
    ADD_SUBDIRECTORY(${CMAKE_CURRENT_SOURCE_DIR}/program)
ENDIF()
# FOR UDNS
ADD_DEFINITIONS(-D HAVE_CONFIG_H)

SET(SHADOWSOCKSNETIO_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/netio/server.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/netio/util.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/netio/dgramsc.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/netio/dns_cache.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/netio/s5.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/netio/handler.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/netio/srv_dns.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/netio/srv_dgram.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/netio/srv_tcp.c

        ${CMAKE_CURRENT_SOURCE_DIR}/src/netio/udns/parsedns.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/netio/udns/dnsget.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/netio/udns/ex-rdns.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/netio/udns/getopt.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/netio/udns/inet_XtoX.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/netio/udns/rblcheck.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/netio/udns/udns_bl.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/netio/udns/udns_init.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/netio/udns/udns_codes.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/netio/udns/udns_dn.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/netio/udns/udns_dntosp.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/netio/udns/udns_jran.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/netio/udns/udns_misc.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/netio/udns/udns_parse.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/netio/udns/udns_resolver.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/netio/udns/udns_rr_a.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/netio/udns/udns_rr_mx.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/netio/udns/udns_rr_naptr.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/netio/udns/udns_rr_ptr.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/netio/udns/udns_rr_srv.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/netio/udns/udns_rr_txt.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/netio/udns/udns_XtoX.c
        )

SET(TLSFLAT_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/tls-flat/tlsflat.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/tls-flat/root.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/tls-flat/handler.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/tls-flat/crt_pool.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/tls-flat/tls.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/tls-flat/tls_send.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/tls-flat/tls_recv.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/tls-flat/tls_handshake.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/tls-flat/tls_transmit.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/tls-flat/util.c
        )

SET(SHADOWSOCKSCRYPTO_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/launch.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/util.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/handler.c

        ${CMAKE_CURRENT_SOURCE_DIR}/src/comm/list.c

        ${SHADOWSOCKSNETIO_SRC}
        ${TLSFLAT_SRC}
        )

ADD_LIBRARY(shadowsocks-crypto STATIC ${SHADOWSOCKSCRYPTO_SRC})
TARGET_LINK_LIBRARIES(shadowsocks-crypto mbedtls uv_a)

if (MSVC)
    TARGET_COMPILE_OPTIONS(shadowsocks-crypto PRIVATE "/utf-8")
endif()