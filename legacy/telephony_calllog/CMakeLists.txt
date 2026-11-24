cmake_minimum_required(VERSION 3.20)

project(LegacyTelephonyCallLog LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_library(calllog STATIC src/calllog.c)
target_include_directories(calllog PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

add_executable(calllog_demo src/main.c)
target_link_libraries(calllog_demo PRIVATE calllog)

add_executable(evidence_demo src/evidence_demo.c)
target_link_libraries(evidence_demo PRIVATE calllog)

add_executable(c_api_demo examples/c_api_demo.c)
target_link_libraries(c_api_demo PRIVATE calllog)

enable_testing()
add_executable(test_calllog tests/c/test_calllog.c)
target_link_libraries(test_calllog PRIVATE calllog)
add_test(NAME legacy_calllog_tests COMMAND test_calllog)
set_tests_properties(
    legacy_calllog_tests
    PROPERTIES WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)
