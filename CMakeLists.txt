cmake_minimum_required(VERSION 3.0.0)
project(orc VERSION 0.1.0)

include(CTest)
enable_testing()

add_library(orc_obj OBJECT orc.c)
add_executable(orc main.c $<TARGET_OBJECTS:orc_obj>)
# add_executable(orc_breakpoints orc_breakpoints.c $<TARGET_OBJECTS:orc_obj>)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
