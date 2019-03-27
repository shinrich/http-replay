cmake_minimum_required(VERSION 3.12)

project(replay-client)
set(CMAKE_CXX_STANDARD 17)
include(GNUInstallDirs)

find_package(swoc++ CONFIG REQUIRED)
find_package(yaml-cpp CONFIG REQUIRED)

add_executable(replay-client
    replay-client.cc
)

target_link_libraries(replay-client PUBLIC swoc++::swoc++ yaml-cpp lib-tscore)
target_include_directories(replay-client PRIVATE ../include)

install(TARGETS replay-client
    EXPORT replay-client-config
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
install(EXPORT replay-client-config
    NAMESPACE replay-clientl::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/replay-client
    )
export(TARGETS replay-client FILE replay-client-config.cmake)
