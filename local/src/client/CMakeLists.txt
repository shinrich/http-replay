cmake_minimum_required(VERSION 3.12)

project(replay-client)
set(CMAKE_CXX_STANDARD 17)
include(GNUInstallDirs)

set(CMAKE_CXX_FLAGS_DEBUG "-g")

set(OPENSSL_ROOT_DIR /opt/oath/openssl/1.1.1)
find_package(OpenSSL REQUIRED)
find_package(swoc++ CONFIG REQUIRED)
find_package(yaml-cpp CONFIG REQUIRED)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(replay-client
    replay-client.cc
)

target_link_libraries(replay-client PUBLIC lib-replay-core swoc++::swoc++ yaml-cpp Threads::Threads OpenSSL::SSL OpenSSL::Crypto)

install(TARGETS replay-client
    EXPORT replay-client-config
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
install(EXPORT replay-client-config
    NAMESPACE replay-clientl::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/replay-client
    )
export(TARGETS replay-client FILE replay-client-config.cmake)
