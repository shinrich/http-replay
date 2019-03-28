cmake_minimum_required(VERSION 3.12)

project(lib-replay-core)
set(CMAKE_CXX_STANDARD 17)
include(GNUInstallDirs)

find_package(swoc++ CONFIG REQUIRED)

add_library(lib-replay-core STATIC
    ArgParser.cc
    HttpReplay.cc
)

target_link_libraries(lib-replay-core PUBLIC swoc++::swoc++)
#target_include_directories(lib-replay-core swoc::swoc)

install(TARGETS lib-replay-core
    EXPORT lib-replay-core-config
    ARCHIVE DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
install(EXPORT lib-replay-core-config
    NAMESPACE replay-core::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/replay-core
    )
export(TARGETS lib-replay-core FILE lib-replay-core-config.cmake)
