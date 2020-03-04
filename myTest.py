#!/usr/bin/python

from bcc import BPF
import yaml

ebpf_base_filename = 'ebpf.c'
ebpf_handler_filename = 'onEvent.c'
filter_filename = 'filter.yaml'

with open(ebpf_base_filename, 'r') as ebpfilebase:
    ebpf_base_str = ebpfilebase.read()

with open(ebpf_handler_filename, 'r') as ebpfilehandler:
    ebpf_handler_str = ebpfilehandler.read()

with open(filter_filename, 'r') as filterfile:
    filters = yaml.load(filterfile, Loader=yaml.FullLoader)

for call in filters["syscalls"]:
    #print(call)
    ebpf_base_str += ebpf_handler_str.replace('EVENTNAME', call)

bpf = BPF(text=ebpf_base_str)

for call in filters["syscalls"]:
    syscall_fname = bpf.get_syscall_fnname(call)
    print(syscall_fname)
    bpf.attach_kprobe(syscall_fname, fn_name="on_" + call)

print(ebpf_base_str)
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "SYSCALL"))

start = 0


def print_event(cpu, data, size):
    global start
    event = bpf["events"].event(data)
    if start == 0:
        start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    print(b"%-18.9f %-16s %-6d %s" % (time_s, event.comm, event.pid, event.call))


bpf["events"].open_perf_buffer(print_event)

while 1:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
