#!/usr/bin/python

from bcc import BPF
import sys
import getopt

syscall_id_list = "execve", "exit", "open", "close", "mount", "unlink"
bpf = None
start = 0
ebpf_base_filename = 'ebpf2.c'
trace_filename = 'tracefile.txt'
tracefile = None
mode_trace = False


class TraceReader:

    def __init__(self, filename):
        self.offset = 0
        self.filename = filename
        self.tracefile = None

    def open(self):
        self.tracefile = open(self.filename, 'r+')

    def get_next_epoch_chunk(self):
        tmp_dict = {}
        line = self.tracefile.readline()
        offset = self.tracefile.tell()
        if not line:
            return None
        fields = line.split()
        current_epoch = fields[0]
        while True:
            container_id = fields[1]
            syscall_id = fields[2]
            if tmp_dict[container_id] is None:
                tmp_bag = {syscall_id: 1}
                tmp_dict.update({container_id: tmp_bag})
            else:
                tmp_bag = tmp_dict[container_id]
                tmp_bag[syscall_id] += 1
            line = self.tracefile.readline()
            if not line:
                return tmp_dict
            fields = line.split()
            next_epoch = fields[0]
            if next_epoch != current_epoch:
                self.tracefile.seek(offset)
                return tmp_dict
            else:
                offset = self.tracefile.tell()


def print_event(cpu, data, size):
    global start, tracefile, mode_trace
    event = bpf["events"].event(data)
    if start == 0:
        start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    if mode_trace:
        epoch = int(time_s)
        tracefile.write("%d %s %d\n" % (epoch, event.uts_name, event.call))
    print(b"%-18.9f %-16s %-16s %-16d %-10d %-16d %-10s %s" % (
        time_s, event.uts_name, event.comm, event.real_pid, event.ns_pid, event.ns_id, syscall_id_list[event.call],
        event.path))


def main(argv):
    global syscall_id_list, bpf, start, ebpf_base_filename, trace_filename, tracefile, mode_trace
    try:
        opts, args = getopt.getopt(argv, "t")
    except getopt.GetoptError:
        print 'Invalid Arguments'
        sys.exit(2)
    for opt, args in opts:
        if opt == '-t':
            mode_trace = True

    with open(ebpf_base_filename, 'r') as ebpfilebase:
        ebpf_base_str = ebpfilebase.read()
    bpf = BPF(text=ebpf_base_str)
    print("These Syscalls will be tracked:\n")
    for x in syscall_id_list:
        syscall_fname = bpf.get_syscall_fnname(x)
        print(syscall_fname)
        bpf.attach_kprobe(syscall_fname, fn_name="syscall__" + x)
    print("\n%-18s %-16s %-16s %-16s %-10s %-16s %-10s %s" % (
        "TIME(s)", "UTS_NAME", "COMM", "REAL_PID", "NS_PID", "NS_ID", "SYSCALL", "PATH"))
    start = 0
    bpf["events"].open_perf_buffer(print_event)

    with open(trace_filename, 'w+') as tracefile:
        while True:
            try:
                bpf.perf_buffer_poll()
            except KeyboardInterrupt:
                break


if __name__ == "__main__":
    main(sys.argv[1:])
