#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/utsname.h>

enum syscall_id{
SYS_EXECVE,
SYS_EXIT,
SYS_OPEN,
SYS_CLOSE,
SYS_MOUNT,
SYS_UNLINK,
};

typedef struct {
    u32 real_pid;
    u32 ns_pid;
    u32 ns_id;
    u32 mnt_id;
    u64 ts;
    char comm[TASK_COMM_LEN];
    char uts_name[TASK_COMM_LEN];
    enum syscall_id call;
    char path[128];
} data_t;

BPF_HASH(pids_map, u32, u32);
BPF_PERF_OUTPUT(events);

static u32 get_task_pid_ns_id(struct task_struct *task)
{
    return task->nsproxy->pid_ns_for_children->ns.inum;
}

static u32 get_task_ns_pid(struct task_struct *task)
{
    return task->thread_pid->numbers[task->nsproxy->pid_ns_for_children->level].nr;
}

static char * get_task_uts_name(struct task_struct *task)
{
    return task->nsproxy->uts_ns->name.nodename;
}

static u32 add_pid_ns_if_needed()
{
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    u32 pid_ns = get_task_pid_ns_id(task);
    if (pids_map.lookup(&pid_ns) != 0)
        // Container pidns was already added to map
        return pid_ns;

    // If pid equals 1 - start tracing the container
    if (get_task_ns_pid(task) == 1) {
        // A new container/pod was started - add pid namespace to map
        pids_map.update(&pid_ns, &pid_ns);
        return pid_ns;
    }

    // Not a container/pod
    return 0;
}

static void remove_pid_ns_if_needed()
{
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    u32 pid_ns = get_task_pid_ns_id(task);
    if (pids_map.lookup(&pid_ns) != 0) {
        // If pid equals 1 - stop tracing this pid namespace
        if (get_task_ns_pid(task) == 1) {
            pids_map.delete(&pid_ns);
        }
    }
}

static int is_container()
{
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    u32 task_pid_ns = get_task_pid_ns_id(task);

    u32 *pid_ns = pids_map.lookup(&task_pid_ns);
    if (pid_ns == 0)
        return 0;

    return *pid_ns;
}

static int init_data(data_t *data){
    struct task_struct *task;
    task = (struct task_struct *) bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    if (uts_name)
        bpf_probe_read_str(&data->uts_name, TASK_COMM_LEN, uts_name);
    data->ns_pid = get_task_ns_pid(task);
    data->ns_id = get_task_pid_ns_id(task);
    data->real_pid = bpf_get_current_pid_tgid();
    data->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    return 0;
}

int syscall__execve(struct pt_regs *ctx, const char __user *filename) {

    data_t data = {};
    add_pid_ns_if_needed();
    if(!is_container())
        return 0;
    init_data(&data);
    data.call = SYS_EXECVE;
    bpf_probe_read_str(data.path, sizeof(data.path), filename);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int syscall__exit(struct pt_regs *ctx) {

    data_t data = {};
    if(!is_container())
        return 0;
    init_data(&data);
    data.call = SYS_EXIT;
    remove_pid_ns_if_needed();
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

static int trace_generic(struct pt_regs *ctx, u32 id)
{
    if(!is_container())
        return 0;
    data_t data = {};
    init_data(&data);
    data.call = id;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

#define TRACE_SYSCALL(name, id)                                         \
int syscall__##name(struct pt_regs *ctx)                                \
{                                                                       \
    trace_generic(ctx, id);                                                  \
    return 0;                                                           \
}                                                                       \

TRACE_SYSCALL(open, SYS_OPEN);
TRACE_SYSCALL(close, SYS_CLOSE);
TRACE_SYSCALL(mount, SYS_MOUNT);
TRACE_SYSCALL(unlink, SYS_UNLINK);