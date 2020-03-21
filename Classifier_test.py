#!/usr/bin/python

from bcc import BPF
from optparse import OptionParser
import ctypes

syscall_id_list = ["execve", "execveat", "exit", "mmap", "mprotect", "clone", "fork", "vfork", "newstat",
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
trace_filename = 'tracefile.txt'
tracefile = None
window_size = 10


class SharedConfig(object):
    CONFIG_TASK_MODE = 0
    CONFIG_CONTAINER_MODE = 1


class SharedTaskname(ctypes.Structure):
    _fields_ = [("name", ctypes.c_char * 16)]


class BagDb:

    def __init__(self, container_id):
        self.container_id = container_id
        self.trace_filen = container_id + '.trace'
        self.trace_offset = 0
        self.list_filen = container_id + '.list'
        self.lookup_names = []
        self.bags_in_window = []
        self.bag_db = {}

    def init_lookup_names(self):
        tmp_list = []
        with open(self.list_filen, 'r+') as list_file:
            line = list_file.readline()
            fields = line.split()
            while line and len(fields) == 3:
                new_tup = (fields[0], fields[1], fields[2])
                tmp_list.append(new_tup)
                line = list_file.readline()
                fields = line.split()
        call_types = len(tmp_list)
        self.lookup_names = [(int(x[0]), x[2]) for x in tmp_list if int(x[1]) > call_types]
        self.lookup_names.append((-1, "others"))

    def lookup_index(self, num):
        try:
            return [x[0] for x in self.lookup_names].index(num)
        except ValueError:
            return -1

    def create_db(self):
        with open(self.trace_filen, 'r+') as trace_file:
            chunk_curr = self.get_next_chunk(trace_file)
            while chunk_curr is not None:
                self.bags_in_window.append(chunk_curr)
                if len(self.bags_in_window) == window_size:
                    self.add_bag_to_db(self.create_bag_from_window())
                    self.bags_in_window.pop(0)
                chunk_curr = self.get_next_chunk(trace_file)

    def create_bag_from_window(self):
        bag_tmp = len(self.lookup_names) * [0]
        for elem in self.bags_in_window:
            bag_tmp = [x + y for x, y in zip(bag_tmp, elem)]
        return tuple(bag_tmp)

    def add_bag_to_db(self, bag):
        if self.bag_db.get(bag) is None:
            self.bag_db.update({bag: 1})
        else:
            self.bag_db[bag] += 1

    def get_next_chunk(self, trace_file):
        line = trace_file.readline()
        fields = line.split()
        chunk_tmp = len(self.lookup_names) * [0]
        while line and len(fields) == 3:
            chunk_tmp[self.lookup_index(int(fields[2]))] += 1
            curr_epoch = fields[0]
            line = trace_file.readline()
            if not (line and len(fields) == 3):
                return chunk_tmp
            else:
                fields = line.split()
                next_epoch = fields[0]
                if next_epoch != curr_epoch:
                    trace_file.seek(self.trace_offset)
                    return chunk_tmp
                else:
                    self.trace_offset = trace_file.tell()
        return None


def on_bpf_event(cpu, data, size):
    global time_start
    event = bpf["events"].event(data)
    if time_start == 0:
        time_start = event.ts
    time_s = (float(event.ts - time_start)) / 1000000000
    epoch = int(time_s)
    print(b"%-18.9f %-16s %-16s %-16d %-10d %-16d %-10s %s" % (
        time_s, event.uts_name, event.comm, event.real_pid, event.ns_pid, event.ns_id, syscall_id_list[event.call],
        event.path))


def ebpf_listen():
    global cli_options, syscall_id_list, syscall_id_ret_list, bpf, ebpf_filename

    with open(ebpf_filename, 'r') as ebpf_file:
        ebpf_base_str = ebpf_file.read()

    bpf = BPF(text=ebpf_base_str)

    # Passing config values to the eBPF program through already initialized maps

    map_index = 0
    if cli_options.task_id:
        key = ctypes.c_uint32(SharedConfig.CONFIG_TASK_MODE)
        bpf["config_map"][key] = ctypes.c_uint32(True)
        strct = SharedTaskname()
        strct.name = cli_options.task_id
        key = ctypes.c_uint32(map_index)
        bpf["taskname_buf"][key] = strct
    elif cli_options.container_id:
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

    # Attaching kprobes for syscalls.
    # execve, execveat and exit are mandatory for tracking the containers

    for x in syscall_id_list:
        syscall_fname = bpf.get_syscall_fnname(x)
        if cli_options.mode_verbose:
            print(syscall_fname)
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


def tracefile_process():
    traces = {}
    occurrencies = {}
    with open(trace_filename) as whole_trace:
        line = whole_trace.readline()
        fields = line.split()
        while line and len(fields) == 3:
            curr_id = fields[1]
            curr_syscall = int(fields[2])
            name_tmp = curr_id + '.trace'
            if traces.get(curr_id) is None:
                new_file = open(name_tmp, 'w+')
                traces.update({curr_id: new_file})
                zeroed_list = list((x, 0) for x in range(len(syscall_id_list)))
                occurrencies.update({curr_id: zeroed_list})
            traces.get(curr_id).writelines(line)
            old_tuple = occurrencies.get(curr_id)[curr_syscall]
            occurrencies.get(curr_id)[curr_syscall] = (old_tuple[0], old_tuple[1] + 1)
            line = whole_trace.readline()
            fields = line.split()

    for container_id, fd in traces.items():
        fd.close()

    for container_id, bag in occurrencies.items():
        name_tmp = container_id + '.list'
        bag.sort(key=lambda tup: tup[1], reverse=True)
        with open(name_tmp, 'w+') as new_file:
            for elem in bag:
                line = [elem[0], ' ', elem[1], ' ', syscall_id_list[elem[0]], '\n']
                new_file.writelines(str(x) for x in line)
    return list(traces.keys())


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


if __name__ == "__main__":
    main()
