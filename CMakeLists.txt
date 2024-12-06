cmake_minimum_required(VERSION 3.5)
project(spp_test)

include_directories("${CMAKE_CURRENT_SOURCE_DIR}")

file(GLOB spp "${CMAKE_CURRENT_SOURCE_DIR}/*.c")

include(FetchContent)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.15.0
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(test_spp_unit ${spp} ${CMAKE_CURRENT_SOURCE_DIR}/test/unit_test.cpp)

target_link_libraries(test_spp_unit PRIVATE gtest gtest_main)

add_executable(test_spp_component ${spp} ${CMAKE_CURRENT_SOURCE_DIR}/test/component_test.cpp)

target_link_libraries(test_spp_component PRIVATE gtest gtest_main)

enable_testing()

add_test(
    NAME spp_unit_test
    COMMAND test_spp_unit
)

add_test(
    NAME spp_component_test
    COMMAND test_spp_component
)
