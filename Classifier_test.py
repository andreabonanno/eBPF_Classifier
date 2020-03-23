#!/usr/bin/python

from bcc import BPF
from optparse import OptionParser
import ctypes

syscall_id_list = ["exit", "execve", "execveat", "mmap", "mprotect", "clone", "fork", "vfork", "newstat",
                   "newfstat", "newlstat", "mknod", "mknodat", "dup", "dup2", "dup3",
                   "memfd_create", "socket", "close", "ioctl", "access", "faccessat", "kill", "listen",
                   "connect", "accept", "accept4", "bind", "getsockname", "prctl", "ptrace",
                   "process_vm_writev", "process_vm_readv", "init_module", "finit_module", "delete_module",
                   "symlink", "symlinkat", "getdents", "getdents64", "creat", "open", "openat",
                   "mount", "umount", "unlink", "unlinkat", "setuid", "setgid", "setreuid", "setregid",
                   "setresuid", "setresgid", "setfsuid", "setfsgid"]

syscall_id_ret_list = ["clone", "fork", "vfork"]

cli_options = {}
bpf = None
time_start = 0
ebpf_filename = 'ebpf2.c'
bag_dbs = {}
window_size = 10


class SharedConfig(object):
    CONFIG_TASK_MODE = 0
    CONFIG_CONTAINER_MODE = 1


class SharedTaskname(ctypes.Structure):
    _fields_ = [("name", ctypes.c_char * 16)]


class BagManager:

    def __init__(self, name, wsize):
        self.id = name
        self.filename = name + '.bagdb'
        self.snapshot_curr = None
        self.window_size = wsize
        self.chunks_in_window = []
        self.trace = []
        self.freq = [0] * len(syscall_id_list)
        self.names_lookup = []

    def add_event(self, epoch, call):
        if epoch not in [x[0] for x in self.trace]:
            new_epoch = [0] * len(syscall_id_list)
            self.trace.append([epoch, new_epoch])
        self.trace[-1][1][call] += 1
        self.freq[call] += 1

    def init_lookup_names(self):
        syscall_dinstinct = sum(x > 0 for x in self.freq)
        for idx, x in enumerate(self.freq):
            if x > syscall_dinstinct:
                self.names_lookup.append(idx)

    def lookup_name(self, num):
        try:
            return self.names_lookup.index(num)
        except ValueError:
            return None

    def create_bag_from_window(self):
        tmp_bag = [0] * len(syscall_id_list)
        tmp_res = [0] * len(self.names_lookup)
        for chunk in self.chunks_in_window:
            tmp_bag = [sum(x) for x in zip(tmp_bag, chunk)]
        count_others = 0
        for idx, x in enumerate(tmp_bag):
            res_lookup = self.lookup_name(idx)
            if res_lookup is None:
                count_others += x
            else:
                tmp_res[res_lookup] += x
        tmp_res.append(count_others)
        self.snapshot_curr = tuple(tmp_res)

    def process_trace(self):
        window_space = self.window_size
        while len(self.trace) > 0:
            if window_space > 0:
                self.chunks_in_window.append(self.trace.pop(0)[1])
            self.create_bag_from_window()
            self.chunks_in_window.pop(0)
            self.chunks_in_window.append(self.trace.pop(0)[1])


def on_bpf_event(cpu, data, size):
    global time_start, cli_options, bag_dbs, window_size
    event = bpf["events"].event(data)
    if time_start == 0:
        time_start = event.ts
    time_s = (float(event.ts - time_start)) / 1000000000
    epoch = int(time_s)
    print(b"%-18.9f %-16s %-16s %-16d %-10d %-16d %-10s %s" % (
        time_s, event.uts_name, event.comm, event.real_pid, event.ns_pid, event.ns_id, syscall_id_list[event.call],
        event.path))
    if cli_options.mode_learn:
        db_name = event.uts_name
        if cli_options.task_id:
            db_name = cli_options.task_id
        elif cli_options.container_id:
            db_name = cli_options.container_id
        if db_name not in bag_dbs:
            new_db = BagManager(db_name, window_size)
            bag_dbs.update({db_name: new_db})
        bag_dbs[db_name].addEvent(epoch, event.call)


def ebpf_listen():
    global cli_options, syscall_id_list, syscall_id_ret_list, bpf, ebpf_filename

    with open(ebpf_filename, 'r') as ebpf_file:
        ebpf_base_str = ebpf_file.read()

    bpf = BPF(text=ebpf_base_str)

    # Passing config values to the eBPF program through already initialized maps

    map_index = 0
    if cli_options.task_id:
        print("Tracking process named \"%s\"" % cli_options.task_id)
        key = ctypes.c_uint32(SharedConfig.CONFIG_TASK_MODE)
        bpf["config_map"][key] = ctypes.c_uint32(True)
        strct = SharedTaskname()
        strct.name = cli_options.task_id
        key = ctypes.c_uint32(map_index)
        bpf["taskname_buf"][key] = strct
    elif cli_options.container_id:
        print("Tracking container with id %s" % cli_options.container_id)
        key = ctypes.c_uint32(SharedConfig.CONFIG_CONTAINER_MODE)
        bpf["config_map"][key] = ctypes.c_uint32(True)
        strct = SharedTaskname()
        strct.name = cli_options.container_id
        key = ctypes.c_uint32(map_index)
        bpf["taskname_buf"][key] = strct
    else:
        key = ctypes.c_uint32(SharedConfig.CONFIG_TASK_MODE)
        bpf["config_map"][key] = ctypes.c_uint32(False)
        key = ctypes.c_uint32(SharedConfig.CONFIG_CONTAINER_MODE)
        bpf["config_map"][key] = ctypes.c_uint32(False)

    if cli_options.mode_verbose:
        print("%d syscalls will be tracked:" % (len(syscall_id_list)))

    # Attaching kprobes for syscalls and events.
    # execve, execveat and do_exit are mandatory for tracking the containers

    bpf.attach_kprobe(event="do_exit", fn_name="trace_do_exit")
    for x in syscall_id_list[1:]:
        syscall_fname = bpf.get_syscall_fnname(x)
        bpf.attach_kprobe(syscall_fname, fn_name="syscall__" + x)

    # Attaching kretprobes for syscalls
    # fork, vfork and clone are mandatory for tracking child processes

    if cli_options.task_id:
        for x in syscall_id_ret_list:
            syscall_fname = bpf.get_syscall_fnname(x)
            bpf.attach_kretprobe(event=syscall_fname, fn_name="trace_ret_" + x)

    print("\n%-18s %-16s %-16s %-16s %-10s %-16s %-10s %s" % (
        "TIME(s)", "UTS_NAME", "COMM", "REAL_PID", "NS_PID", "NS_ID", "SYSCALL", "PATH"))

    bpf["events"].open_perf_buffer(on_bpf_event)

    while True:
        try:
            bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            break


def main():
    global cli_options

    # Dealing with CLI options

    OptParser = OptionParser()
    OptParser.add_option("-l", "--learn", action="store_true", dest="mode_learn", default=False,
                         help="Creates databses of normal behaviour for the items the program listened to")
    OptParser.add_option("-t", "--task", action="store", type="string", dest="task_id", default=None,
                         help="Start the program in task mode. Needs the taskname to track as argument.")
    OptParser.add_option("-c", "--container", action="store", type="string", dest="container_id", default=None,
                         help="Start the program in container mode. Needs the container id to track as argument.")
    OptParser.add_option("-v", "--verbose", action="store_true", dest="mode_verbose", default=False,
                         help="Start the program in verbose mode, printing more info")
    (cli_options, args) = OptParser.parse_args()

    if cli_options.task_id and cli_options.container_id:
        OptParser.error("options -t and -c are mutually exclusive")

    ebpf_listen()
    if cli_options.mode_learn:
        for db in bag_dbs:
            db.init_lookup_names()
            db.process_trace()
            print(db.snapshot_curr)


if __name__ == "__main__":
    main()
