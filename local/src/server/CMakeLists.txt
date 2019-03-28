cmake_minimum_required(VERSION 3.12)

project(replay-server)
set(CMAKE_CXX_STANDARD 17)
include(GNUInstallDirs)

find_package(swoc++ CONFIG REQUIRED)
find_package(yaml-cpp CONFIG REQUIRED)
find_package(Threads REQUIRED)

add_executable(replay-server
    replay-server.cc
)

target_link_libraries(replay-server PUBLIC swoc++::swoc++ yaml-cpp lib-replay-core Threads::Threads)

install(TARGETS replay-server
    EXPORT replay-server-config
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
install(EXPORT replay-server-config
    NAMESPACE replay-serverl::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/replay-server
    )
export(TARGETS replay-server FILE replay-server-config.cmake)
