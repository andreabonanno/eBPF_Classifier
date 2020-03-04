#include <linux/sched.h>

typedef struct {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
    char call[TASK_COMM_LEN];
    //char path[PATH_MAX];
    char path[128];
} data_t;

//BPF_PERCPU_ARRAY(tmp_arr, data_t, 1);
BPF_PERF_OUTPUT(events);

int syscall__execve(struct pt_regs *ctx, const char __user *filename) {

    /*
    u32 key = 0;
    data_t *datatmp = tmp_arr.lookup(&key);
    if(datatmp != NULL){
        datatmp->pid = bpf_get_current_pid_tgid();
        datatmp->ts = bpf_ktime_get_ns();
        strcpy(datatmp->call, "execve");
        bpf_probe_read_str(datatmp->path, sizeof(datatmp->path), filename);
        bpf_get_current_comm(&datatmp->comm, sizeof(datatmp->comm));
        }
    events.perf_submit(ctx, datatmp, sizeof(data_t));
    */

    data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    strcpy(data.call, "execve");
    bpf_probe_read_str(data.path, sizeof(data.path), filename);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int syscall__unlink(struct pt_regs *ctx, const char __user *pathname) {
  data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    strcpy(data.call, "unlink");
    bpf_probe_read_str(data.path, sizeof(data.path), pathname);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

