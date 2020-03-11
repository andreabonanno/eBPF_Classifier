#!/usr/bin/python

from bcc import BPF
from enum import Enum, unique
import yaml


@unique
class Syscalls(Enum):
    SYS_EXECVE, SYS_EXIT, SYS_UNLINK, SYS_OPEN, SYS_CLOSE = range(5)


ebpf_base_filename = 'ebpf2.c'
filter_filename = 'filter2.yaml'

with open(ebpf_base_filename, 'r') as ebpfilebase:
    ebpf_base_str = ebpfilebase.read()

with open(filter_filename, 'r') as filterfile:
    filters = yaml.load(filterfile, Loader=yaml.FullLoader)

bpf = BPF(text=ebpf_base_str)
print("These Syscalls will be tracked:\n")
for call in filters["syscalls"]:
    syscall_fname = bpf.get_syscall_fnname(call)
    print(syscall_fname)
    bpf.attach_kprobe(syscall_fname, fn_name="syscall__" + call)

print("\n%-18s %-16s %-16s %-10s %-16s %-10s %s" % ("TIME(s)", "COMM", "REAL_PID", "NS_PID", "NS_ID", "SYSCALL", "PATH"))

start = 0


def print_event(cpu, data, size):
    global start
    event = bpf["events"].event(data)
    if start == 0:
        start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    print(b"%-18.9f %-16s %-16d %-10d %-16d %-10s %s" % (time_s, event.comm, event.real_pid, event.ns_pid, event.ns_id, Syscalls(event.call).name, event.path))


bpf["events"].open_perf_buffer(print_event)

while 1:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
