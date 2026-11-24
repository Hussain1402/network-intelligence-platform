cmake_minimum_required(VERSION 3.20)

project(NetworkIntelligencePlatform
    VERSION 1.0.0
    LANGUAGES C CXX
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

function(enable_project_warnings target)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang" OR
       CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
    endif()
endfunction()

# PS1: independently reusable C function-execution logging library.
add_library(functionlog STATIC src/functionlog.c)
target_include_directories(functionlog PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
enable_project_warnings(functionlog)

# PS2: network metrics ingestion, anomaly detection, analytics, and trends.
add_library(network_metrics STATIC src/network_metrics.c)
target_include_directories(network_metrics PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
enable_project_warnings(network_metrics)

add_library(network_anomaly STATIC src/network_anomaly.c)
target_include_directories(network_anomaly PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(network_anomaly PUBLIC network_metrics)
enable_project_warnings(network_anomaly)

add_library(network_analytics STATIC src/network_analytics.c)
target_include_directories(network_analytics PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(network_analytics PUBLIC network_metrics network_anomaly)
enable_project_warnings(network_analytics)

add_library(network_trends STATIC src/network_trends.c)
target_include_directories(network_trends PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(network_trends PUBLIC network_metrics)
enable_project_warnings(network_trends)

add_executable(functionlog_c_demo examples/functionlog_c_demo.c)
target_link_libraries(functionlog_c_demo PRIVATE functionlog)
enable_project_warnings(functionlog_c_demo)

add_executable(functionlog_cpp_demo examples/functionlog_cpp_demo.cpp)
target_link_libraries(functionlog_cpp_demo PRIVATE functionlog)
enable_project_warnings(functionlog_cpp_demo)

add_executable(network_anomaly_demo src/network_anomaly_demo.c)
target_link_libraries(network_anomaly_demo PRIVATE network_anomaly)
enable_project_warnings(network_anomaly_demo)

add_executable(network_pipeline_demo src/network_pipeline_demo.c)
target_link_libraries(
    network_pipeline_demo
    PRIVATE network_metrics network_anomaly network_analytics network_trends
)
enable_project_warnings(network_pipeline_demo)

enable_testing()
set(PROJECT_TESTS)

function(add_project_test target source test_name)
    add_executable(${target} ${source})
    target_link_libraries(${target} PRIVATE ${ARGN})
    enable_project_warnings(${target})
    add_test(NAME ${test_name} COMMAND ${target})
    set(PROJECT_TESTS ${PROJECT_TESTS} ${test_name} PARENT_SCOPE)
endfunction()

add_project_test(
    test_functionlog tests/c/test_functionlog.c
    functionlog_unit_tests functionlog
)
add_project_test(
    test_functionlog_analytics tests/c/test_functionlog_analytics.c
    functionlog_analytics_tests functionlog
)
add_project_test(
    test_functionlog_json tests/c/test_functionlog_json.c
    functionlog_json_tests functionlog
)

if(WIN32)
    add_project_test(
        test_functionlog_concurrency tests/c/test_functionlog_concurrency.c
        functionlog_concurrency_tests functionlog
    )
endif()

add_project_test(
    test_network_metrics tests/c/test_network_metrics.c
    network_metrics_unit_tests network_metrics
)
add_project_test(
    test_network_anomaly tests/c/test_network_anomaly.c
    network_anomaly_unit_tests network_anomaly
)
add_project_test(
    test_network_analytics tests/c/test_network_analytics.c
    network_analytics_unit_tests network_analytics
)
add_project_test(
    test_network_trends tests/c/test_network_trends.c
    network_trends_unit_tests network_trends
)

set_tests_properties(
    ${PROJECT_TESTS}
    PROPERTIES WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)
