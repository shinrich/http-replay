cmake_minimum_required(VERSION 3.12)

project(lib-tscore)
set(CMAKE_CXX_STANDARD 17)
include(GNUInstallDirs)

find_package(swoc++ CONFIG REQUIRED)

add_library(lib-tscore
    ArgParser.cc
)

target_link_libraries(lib-tscore PUBLIC swoc++::swoc++)

install(TARGETS lib-tscore
    EXPORT lib-tscore-config
    ARCHIVE DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
install(EXPORT lib-tscore-config
    NAMESPACE tscorel::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/tscore
    )
export(TARGETS lib-tscore FILE lib-tscore-config.cmake)
