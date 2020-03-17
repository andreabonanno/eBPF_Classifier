#!/usr/bin/python

from bcc import BPF
import sys
import getopt

syscall_id_list = "execve", "exit", "open", "close", "mount", "unlink"
bpf = None
start = 0
ebpf_filename = 'ebpf2.c'
trace_filename = 'tracefile.txt'
tracefile = None
window_size = 10
mode_trace = False
mode_listen = False


class bagDb:

    def __init__(self, container_id):
        self.container_id = container_id
        self.trace_filen = container_id + '.trace'
        self.trace_offset = 0
        self.list_filen = container_id + '.list'
        self.lookup_names = []
        self.bags_in_window = []
        self.bag_db = {}

    def init_lookup_names(self):
        with open(self.list_filen, 'r+') as list_file:
            line = list_file.readline()
            fields = line.split()
            while line and len(fields) == 3:
                new_tup = (fields[0], fields[2])
                self.lookup_names.append(new_tup)
                line = list_file.readline()
                fields = line.split()

    def lookup_index(self, num):
        return [x[0] for x in self.lookup_names].index(num)

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
            chunk_tmp[self.lookup_index(fields[2])] += 1
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


def ebpf_listen():
    global syscall_id_list, bpf, ebpf_filename, trace_filename, tracefile, start

    with open(ebpf_filename, 'r') as ebpf_file:
        ebpf_base_str = ebpf_file.read()
    bpf = BPF(text=ebpf_base_str)
    print("These Syscalls will be tracked:\n")
    for x in syscall_id_list:
        syscall_fname = bpf.get_syscall_fnname(x)
        print(syscall_fname)
        bpf.attach_kprobe(syscall_fname, fn_name="syscall__" + x)
    print("\n%-18s %-16s %-16s %-16s %-10s %-16s %-10s %s" % (
        "TIME(s)", "UTS_NAME", "COMM", "REAL_PID", "NS_PID", "NS_ID", "SYSCALL", "PATH"))
    start = 0
    bpf["events"].open_perf_buffer(on_bpf_event)

    with open(trace_filename, 'w+') as tracefile:
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


def main(argv):
    global trace_filename, tracefile, mode_listen, mode_trace
    try:
        opts, args = getopt.getopt(argv, "tl")
    except getopt.GetoptError:
        print 'Invalid Arguments'
        sys.exit(2)
    for opt, args in opts:
        if opt == '-t':
            mode_trace = True
        elif opt == '-l':
            mode_listen = True
    if mode_listen:
        ebpf_listen()
    container_discovered = tracefile_process()
    if len(container_discovered) == 0:
        print("No container has been discovered")
    else:
        print("\n%d containers has been discovered, with id:\n" % (len(container_discovered)))
        print(container_discovered)
    for container_id in container_discovered:
        db = bagDb(container_id)
        db.init_lookup_names()
        db.create_db()
        print("A System call bag for %s has been classified:\n" % container_id)
        print(db.bag_db)


if __name__ == "__main__":
    main(sys.argv[1:])
