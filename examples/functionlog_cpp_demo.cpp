#include "functionlog.h"

#include <iostream>
#include <stdexcept>

template <typename Function>
auto monitored(const char *name, const char *caller, Function function)
    -> decltype(function())
{
    unsigned long long execution_id = 0;

    FunctionLogResult result =
        functionlog_enter(name, caller, &execution_id);

    if (result != FUNCTIONLOG_OK) {
        throw std::runtime_error("Unable to start function monitoring");
    }

    try {
        auto value = function();

        result = functionlog_exit(
            execution_id, FUNCTIONLOG_SUCCESS, 0, nullptr
        );

        if (result != FUNCTIONLOG_OK) {
            throw std::runtime_error(
                "Unable to record successful function completion"
            );
        }

        return value;
    }
    catch (const std::exception &exception) {
        result = functionlog_exit(
            execution_id, FUNCTIONLOG_FAILED, 2001, exception.what()
        );

        if (result != FUNCTIONLOG_OK) {
            std::cerr << "Warning: failed to record exception for "
                      << name << ". Logger result: "
                      << static_cast<int>(result) << '\n';
        }

        throw;
    }
    catch (...) {
        result = functionlog_exit(
            execution_id, FUNCTIONLOG_FAILED, 2002,
            "Unknown C++ exception"
        );

        if (result != FUNCTIONLOG_OK) {
            std::cerr << "Warning: failed to record unknown exception for "
                      << name << ". Logger result: "
                      << static_cast<int>(result) << '\n';
        }

        throw;
    }
}

int validate_input()
{
    return monitored("validate_input", "process_request", []() {
        return 1;
    });
}

int process_request()
{
    return monitored("process_request", "main", []() {
        return validate_input();
    });
}

int process_invalid_request()
{
    return monitored("process_invalid_request", "main", []() -> int {
        throw std::runtime_error("Invalid request detected");
    });
}

int main()
{
    if (functionlog_init() != FUNCTIONLOG_OK) {
        std::cerr << "Logger initialization failed.\n";
        return 1;
    }

    int application_failed = 0;

    try {
        std::cout << "Valid request result: "
                  << process_request() << '\n';

        try {
            process_invalid_request();
        }
        catch (const std::exception &exception) {
            std::cout << "Caught expected exception: "
                      << exception.what() << '\n';
        }

        if (functionlog_export_csv(
                "output/function_execution_cpp_logs.csv")
            != FUNCTIONLOG_OK) {
            std::cerr << "C++ CSV export failed.\n";
            application_failed = 1;
        } else {
            std::cout << "C++ execution logs exported successfully.\n";
        }
    }
    catch (const std::exception &exception) {
        std::cerr << "Unexpected error: " << exception.what() << '\n';
        application_failed = 1;
    }

    functionlog_cleanup();
    return application_failed;
}
