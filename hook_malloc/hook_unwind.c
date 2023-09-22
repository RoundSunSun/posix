#define _GNU_SOURCE
#define UNW_LOCAL_ONLY
#define LOG_BUFFER_SIZE 1024 * 1024

#include <dlfcn.h>
#include <inttypes.h>
#include <libunwind.h>
#include <execinfo.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sched.h>

// gcc -o hook.so -g -fPIC -shared hook.c -ldl -lpthread -lunwind
// LD_PRELOAD=./hook.so ./myexecutable
// in GDB: set exec-wrapper env 'LD_PRELOAD=./hook.so'

#define STACKCALL __attribute__((regparm(1), noinline))
void **STACKCALL getEBP(void)
{
    void **ebp = NULL;
    __asm__ __volatile__("mov %%rbp, %0;\n\t"
                         : "=m"(ebp)  /* output */
                         :            /* input */
                         : "memory"); /* 不受影响的寄存器 */
    return (void **)(*ebp);
}
int my_backtrace(void **buffer, int size)
{
    int frame = 0;
    void **ebp;
    void **ret = NULL;
    unsigned long long func_frame_distance = 0;
    if (buffer != NULL && size > 0)
    {
        ebp = getEBP();
        func_frame_distance = (unsigned long long)(*ebp) - (unsigned long long)ebp;
        while (ebp && frame < size && (func_frame_distance < (1ULL << 24)) //assume function ebp more than 16M
               && (func_frame_distance > 0))
        {
            ret = ebp + 1;
            buffer[frame++] = *ret;
            ebp = (void **)(*ebp);
            func_frame_distance = (unsigned long long)(*ebp) - (unsigned long long)ebp;
        }
    }
    return frame;
}

pthread_spinlock_t spinlock;
int guard = 0;
int flag = 0;
int log_buffer_offset;
char log_buffer[LOG_BUFFER_SIZE];
void *(*real_malloc)(size_t size);

void *malloc(size_t size)
{
    // initialization
    if (flag == 0)
    {
        flag = 1;
        guard++;
        real_malloc = dlsym(RTLD_NEXT, "malloc");
        pthread_spin_init(&spinlock, PTHREAD_PROCESS_SHARED);
        guard--;
    }

    // call real malloc
    void *chunk = real_malloc(size);

    // get backtrace
    pid_t tid = syscall(SYS_gettid);
    int policy = sched_getscheduler(tid);
    if (policy == SCHED_FIFO && guard == 0)
    {
        // get lock
        pthread_spin_lock(&spinlock);
        guard++;

        // backtrace
        void *callstack[128];
        int frames = unw_backtrace(callstack, 50);
        char **symbols = backtrace_symbols(callstack, frames);
        if (symbols == NULL)
        {
            perror("backtrace_symbols");
        }

        // logging
        pid_t pid = getpid();
        memset(log_buffer, 0, sizeof(log_buffer));
        log_buffer_offset += snprintf(log_buffer + log_buffer_offset, sizeof(log_buffer) - log_buffer_offset, "PID(%d) TID(%d) POLICY(%d) MALLOC(%4ld) at %p, FRAMES(%d)\n", pid, tid, policy, size, chunk, frames);
        for (int i = 1; i < frames; i++)
        {
            log_buffer_offset += snprintf(log_buffer + log_buffer_offset, sizeof(log_buffer) - log_buffer_offset, "CALL STACK %d:  %s\n", i, symbols[i]);
        }
        free(symbols);
        ssize_t bytes_written = write(1022, log_buffer, strlen(log_buffer));
        if (bytes_written == -1)
        {
            perror("write fd failed");
        }
        memset(log_buffer, 0, LOG_BUFFER_SIZE);
        log_buffer_offset = 0;

        // release lock
        guard--;
        pthread_spin_unlock(&spinlock);
    }
    return chunk;
}
