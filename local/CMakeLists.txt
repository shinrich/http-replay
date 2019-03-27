cmake_minimum_required(VERSION 3.12)
set(CMAKE_CXX_STANDARD 17)

set(INSTALL_DIR ${CMAKE_HOME_DIRECTORY})
if(NOT DEFINED CMAKE_PREFIX_PATH)
    set(CMAKE_PREFIX_PATH ${INSTALL_DIR})
endif()

add_subdirectory(src/tscore)
add_subdirectory(src/client)
add_subdirectory(src/server)

add_custom_target(clang-format COMMAND ${CMAKE_HOME_DIRECTORY}/tools/clang-format.sh src/tscore src/client src/server)
