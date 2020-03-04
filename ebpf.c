#include <linux/sched.h>

struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
    char call[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

