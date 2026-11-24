#include "functionlog.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#define THREAD_COUNT 8
#define EXECUTIONS_PER_THREAD 100

static DWORD WINAPI worker_thread(LPVOID argument)
{
    int worker_id = *(int *)argument;

    for (int i = 0; i < EXECUTIONS_PER_THREAD; i++) {
        unsigned long long id = 0;

        FunctionLogResult result = functionlog_enter(
            "worker_function",
            "worker_thread",
            &id
        );

        if (result != FUNCTIONLOG_OK) {
            return 1;
        }

        if (functionlog_exit(
                id,
                FUNCTIONLOG_SUCCESS,
                0,
                NULL
            ) != FUNCTIONLOG_OK) {
            return 1;
        }
    }

    printf("Worker %d completed.\n", worker_id);
    return 0;
}


typedef struct {
    unsigned long long execution_id;
    FunctionLogResult result;
} CrossThreadExitAttempt;

static DWORD WINAPI cross_thread_exit_attempt(LPVOID argument)
{
    CrossThreadExitAttempt *attempt =
        (CrossThreadExitAttempt *)argument;

    attempt->result = functionlog_exit(
        attempt->execution_id,
        FUNCTIONLOG_SUCCESS,
        0,
        NULL
    );

    return 0;
}
int main(void)
{
    HANDLE threads[THREAD_COUNT];
    int worker_ids[THREAD_COUNT];

    if (functionlog_init() != FUNCTIONLOG_OK) {
        fprintf(stderr, "Logger initialization failed.\n");
        return 1;
    }
    /* An execution must not be completed by a different thread. */
    unsigned long long main_thread_id = 0;

    if (functionlog_enter(
            "main_thread_function", "main", &main_thread_id
        ) != FUNCTIONLOG_OK) {
        fprintf(stderr, "Main-thread execution entry failed.\n");
        functionlog_cleanup();
        return 1;
    }

    CrossThreadExitAttempt attempt;
    attempt.execution_id = main_thread_id;
    attempt.result = FUNCTIONLOG_OK;

    HANDLE cross_thread = CreateThread(
        NULL, 0, cross_thread_exit_attempt, &attempt, 0, NULL
    );

    if (cross_thread == NULL) {
        fprintf(stderr, "Could not create cross-thread test worker.\n");
        functionlog_cleanup();
        return 1;
    }

    DWORD cross_thread_wait =
        WaitForSingleObject(cross_thread, INFINITE);
    CloseHandle(cross_thread);

    if (cross_thread_wait != WAIT_OBJECT_0 ||
        attempt.result != FUNCTIONLOG_ERROR_INVALID_ARGUMENT) {
        fprintf(stderr, "Cross-thread exit was not rejected.\n");
        functionlog_cleanup();
        return 1;
    }

    /* The owning thread must still be able to complete the execution. */
    if (functionlog_exit(
            main_thread_id, FUNCTIONLOG_SUCCESS, 0, NULL
        ) != FUNCTIONLOG_OK) {
        fprintf(stderr, "Owning thread could not complete execution.\n");
        functionlog_cleanup();
        return 1;
    }

    printf("Cross-thread exit rejection test passed.\n");

    for (int i = 0; i < THREAD_COUNT; i++) {
        worker_ids[i] = i + 1;

        threads[i] = CreateThread(
            NULL,
            0,
            worker_thread,
            &worker_ids[i],
            0,
            NULL
        );

        if (threads[i] == NULL) {
            fprintf(stderr, "Failed to create worker %d.\n", i + 1);
            return 1;
        }
    }

    DWORD wait_result = WaitForMultipleObjects(
        THREAD_COUNT,
        threads,
        TRUE,
        INFINITE
    );

    if (wait_result == WAIT_FAILED) {
        fprintf(stderr, "Failed waiting for worker threads.\n");
        return 1;
    }

    int failed = 0;

    for (int i = 0; i < THREAD_COUNT; i++) {
        DWORD exit_code = 1;

        if (!GetExitCodeThread(threads[i], &exit_code) ||
            exit_code != 0) {
            failed = 1;
        }

        CloseHandle(threads[i]);
    }

    if (failed) {
        fprintf(stderr, "One or more workers failed.\n");
        functionlog_cleanup();
        return 1;
    }

    if (functionlog_export_csv(
            "output/functionlog_concurrency_test.csv"
        ) != FUNCTIONLOG_OK) {
        fprintf(stderr, "CSV export failed.\n");
        functionlog_cleanup();
        return 1;
    }

    printf("\nExpected records: %d\n",
           THREAD_COUNT * EXECUTIONS_PER_THREAD);

    printf("Concurrency test completed.\n");

    functionlog_cleanup();
    return 0;
}
