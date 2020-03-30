#!/usr/bin/python

from bcc import BPF
from optparse import OptionParser
import ctypes
import json
import math
import os.path as osp

# This list must match the one in the eBpf program
syscall_id_list = ["exit", "execve", "execveat", "mmap", "mprotect", "clone", "fork", "vfork", "newstat",
                   "newfstat", "newlstat", "mknod", "mknodat", "dup", "dup2", "dup3",
                   "memfd_create", "socket", "close", "ioctl", "access", "faccessat", "kill", "listen",
                   "connect", "accept", "accept4", "bind", "getsockname", "prctl", "ptrace",
                   "process_vm_writev", "process_vm_readv", "init_module", "finit_module", "delete_module",
                   "symlink", "symlinkat", "getdents", "getdents64", "creat", "open", "openat",
                   "mount", "umount", "unlink", "unlinkat", "setuid", "setgid", "setreuid", "setregid",
                   "setresuid", "setresgid", "setfsuid", "setfsgid"]

# Kretprobes neeeded to track child processes
syscall_id_ret_list = ["clone", "fork", "vfork"]

cli_options = {}
cli_arg_name = None
bpf = None
time_start = 0
ebpf_filename = 'ebpf2.c'
bag_dbs = {}
window_size = 10
epoch_size = 1000


# Indexes of the eBpf map used to pass config to the eBpf program
class SharedConfig(object):
    CONFIG_TASK_MODE = 0
    CONFIG_CONTAINER_MODE = 1


# This struct must match the one defined in the eBpf file
class SharedTaskname(ctypes.Structure):
    _fields_ = [("name", ctypes.c_char * 16)]


class BagManager:

    def __init__(self, name, wsize, esize):
        self.id = name
        self.db_curr = {}
        self.db_old = {}
        self.similarity = 0
        self.similarity_list = []
        self.sim_tresh = 0.99
        self.window_size = wsize
        self.epoch_size = esize
        self.epoch_offst = 0
        self.chunks_in_window = []
        self.trace = []
        self.freq = [0] * len(syscall_id_list)
        self.names_lookup = []
        self.mismatch_count = 0
        self.mismatch_tresh = epoch_size / 10
        self.monitor_events = 0

    def add_event(self, call):
        self.trace.append(call)
        self.freq[call] += 1

    # Keeps correspondece for the global syscall ids and the BagManager specific ids
    # Sysycalls with low occurence are marked as "other"
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

    # Creates a syscall bag from the current sliding window
    def create_bag_from_window(self):
        tmp_bag = [0] * len(self.names_lookup)
        other_count = 0
        for x in self.chunks_in_window:
            index = self.lookup_name(x)
            if index is None:
                other_count += 1
            else:
                tmp_bag[index] += 1
        tmp_bag.append(other_count)
        return tuple(tmp_bag)

    def add_bag_to_db(self, bag):
        if bag in self.db_curr:
            old_t = self.db_curr[bag]
            self.db_curr[bag] = (old_t[0] + 1, old_t[1] + 1)
        else:
            self.db_curr.update({bag: (1, 1)})

    def rotate_db(self):
        self.db_old = dict(self.db_curr)
        for k, v in self.db_curr.items():
            t_count = v[0]
            self.db_curr[k] = (t_count, 0)

    # Syscalls bags are created from a sliding window of size self.window_size
    def process_trace(self):
        window_space = self.window_size
        count = 0
        while len(self.trace) > 0 and window_space > 0:
            self.chunks_in_window.append(self.trace.pop(0))
            window_space -= 1
            count += 1

        while len(self.trace) > 0:
            bag = self.create_bag_from_window()
            self.add_bag_to_db(bag)
            count += 1
            if count == self.epoch_size:
                self.similarity = self.evaluate()
                self.similarity_list.append(self.similarity)
                if self.similarity > self.sim_tresh:
                    return True
                self.rotate_db()
                count = 0
            self.chunks_in_window.pop(0)
            self.chunks_in_window.append(self.trace.pop(0))
        return False

    def monitor_trace(self):
        while len(self.trace) > 0 and len(self.chunks_in_window) < self.window_size:
            self.chunks_in_window.append(self.trace.pop(0))
            self.epoch_offst += 1

        while len(self.trace) > 0 and self.epoch_offst < self.epoch_size:
            bag = self.create_bag_from_window()
            if bag not in self.db_curr:
                self.mismatch_count += 1
                if self.mismatch_count >= self.mismatch_tresh:
                    return True
            self.epoch_offst += 1
            self.chunks_in_window.pop(0)
            self.chunks_in_window.append(self.trace.pop(0))
        if self.epoch_offst == self.epoch_offst:
            self.mismatch_count = 0
            self.epoch_offst = 0
        return False

    def evaluate(self):
        freq_c = []
        freq_t = []
        for k, v in self.db_curr.items():
            freq_c.append(v[1] + 1)
            if k in self.db_old:
                freq_t.append(self.db_old[k][1] + 1)
            else:
                freq_t.append(1)
        return cosine_metric(freq_c, freq_t)

    def to_json_file(self):
        dump_dict = {}
        dump_dict.update({"db_bags": [list(x) for x in self.db_curr]})
        dump_dict.update({"db_freq": [self.db_curr[x][0] for x in self.db_curr]})
        dump_dict.update({"names_lookup": self.names_lookup})
        dump_dict.update({"window_size": self.window_size})
        with open(self.id + ".json", "w") as json_file:
            json_file.write(json.dumps(dump_dict, indent=4))

    def load(self, name):
        with open(name + ".json") as json_file:
            data = json.load(json_file)
        self.window_size = data["window_size"]
        self.names_lookup = data["names_lookup"]
        self.db_curr = {tuple(x): y for x, y in zip(data["db_bags"], data["db_freq"])}


def cosine_metric(v1, v2):
    sumxx, sumxy, sumyy = 0, 0, 0
    for i in range(len(v1)):
        x = v1[i]
        y = v2[i]
        sumxx += x * x
        sumyy += y * y
        sumxy += x * y
    return sumxy / math.sqrt(sumxx * sumyy)


def on_bpf_event(cpu, data, size):
    global time_start, cli_options, cli_arg_name, bag_dbs, window_size
    event = bpf["events"].event(data)
    if time_start == 0:
        time_start = event.ts
    time_s = (float(event.ts - time_start)) / 1000000000
    print(b"%-18.9f %-16s %-16s %-16d %-10d %-16d %-10s %s" % (
        time_s, event.uts_name, event.comm, event.real_pid, event.ns_pid, event.ns_id, syscall_id_list[event.call],
        event.path))

    db_name = event.uts_name
    if cli_options.task_id or cli_options.container_id:
        db_name = cli_arg_name
    if db_name not in bag_dbs:
        new_db = BagManager(db_name, window_size, epoch_size)
        bag_dbs.update({db_name: new_db})
    bag_dbs[db_name].add_event(event.call)


def ebpf_listen():
    global cli_options, cli_arg_name, syscall_id_list, syscall_id_ret_list, bpf, ebpf_filename

    with open(ebpf_filename, 'r') as ebpf_file:
        ebpf_base_str = ebpf_file.read()

    bpf = BPF(text=ebpf_base_str)

    # Passing config values to the eBPF program through already initialized maps

    if cli_options.task_id or cli_options.container_id:
        print("\nTracking item with id \"%s\"\n" % cli_arg_name)
        if cli_options.task_id:
            key = ctypes.c_uint32(SharedConfig.CONFIG_TASK_MODE)
        else:
            key = ctypes.c_uint32(SharedConfig.CONFIG_CONTAINER_MODE)
        bpf["config_map"][key] = ctypes.c_uint32(True)
        strct = SharedTaskname()
        strct.name = cli_arg_name
        key = ctypes.c_uint32(0)
        bpf["taskname_buf"][key] = strct
    else:
        key = ctypes.c_uint32(SharedConfig.CONFIG_TASK_MODE)
        bpf["config_map"][key] = ctypes.c_uint32(False)
        key = ctypes.c_uint32(SharedConfig.CONFIG_CONTAINER_MODE)
        bpf["config_map"][key] = ctypes.c_uint32(False)

    if cli_options.mode_verbose:
        print("%d syscalls will be tracked:\n%s" % (len(syscall_id_list), ", ".join(syscall_id_list)))

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
            if cli_options.mode_monitor:
                if bag_dbs[cli_arg_name].monitor_trace():
                    print("ANOMALY FOUND FOR %s\nMISMATCH COUNT %d\n" % (cli_arg_name, bag_dbs[cli_arg_name].mismatch_count))
                    break
        except KeyboardInterrupt:
            break


def main():
    global cli_options, cli_arg_name

    # Dealing with CLI options

    OptParser = OptionParser()
    OptParser.add_option("-l", "--learn", action="store_true", dest="mode_learn", default=False,
                         help="Creates databses of normal behaviour for the items the program listened to")
    OptParser.add_option("-m", "--monitor", action="store_true", dest="mode_monitor", default=False,
                         help="Monitor the selected process/container for anomalies using a previosly generated "
                              "normal behaviour database")
    OptParser.add_option("-t", "--task", action="store", type="string", dest="task_id", default=None,
                         help="Start the program in task mode. Needs the taskname to track as argument.")
    OptParser.add_option("-c", "--container", action="store", type="string", dest="container_id", default=None,
                         help="Start the program in container mode. Needs the container id to track as argument.")
    OptParser.add_option("-v", "--verbose", action="store_true", dest="mode_verbose", default=False,
                         help="Start the program in verbose mode, printing more info")
    (cli_options, args) = OptParser.parse_args()

    if cli_options.task_id and cli_options.container_id:
        OptParser.error("options -t and -c are mutually exclusive")
    if cli_options.mode_learn and cli_options.mode_monitor:
        OptParser.error("options -l and -m are mutually exclusive")
    cli_arg_name = cli_options.task_id if cli_options.task_id else cli_options.container_id

    # Normal behaviour data must be loaded before starting to listen
    if cli_options.mode_monitor:
        bag_mngr = BagManager(cli_arg_name, window_size, epoch_size)
        if not osp.isfile(cli_arg_name + ".json"):
            print("Normal Behaviour file for %s not found" % cli_arg_name)
            exit(True)
        bag_mngr.load(cli_arg_name)
        bag_dbs.update({cli_arg_name: bag_mngr})
        if cli_options.mode_verbose:
            print("Loaded normal behaviour dataset for %s" % cli_arg_name)

    ebpf_listen()

    # Process and write data to json after listening the process/container
    if cli_options.mode_learn:
        for name, db in bag_dbs.items():
            db.init_lookup_names()
            if db.process_trace() > 0:
                print("Normal behaviour data has been gathered for %s after %d epochs (%d syscalls)" % (
                    cli_arg_name, len(db.similarity_list), len(db.similarity_list) * epoch_size))
            else:
                print("More data needs to be gathered to learn the normal behaviour of %s " % cli_arg_name)
            if cli_options.mode_verbose:
                print("Cosine similarity progression for %s:" % cli_arg_name)
                print(db.similarity_list)
            db.to_json_file()


if __name__ == "__main__":
    main()
