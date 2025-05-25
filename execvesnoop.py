#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# execvesnoop Trace execve() syscalls.
#            For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: execvesnoop [-h] [-T] [-U] [-x] [-p PID] [-t TID]
#                   [--cgroupmap CGROUPMAP] [--mntnsmap MNTNSMAP] [-u UID]
#                   [-d DURATION] [-n NAME] [-e] [-b BUFFER_PAGES] [-i INTERVAL]
#
# Copyright (c) 2024
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import ArgString, BPF
from bcc.containers import filter_by_containers
from bcc.utils import printb
import argparse
from datetime import datetime, timedelta
import os
import ctypes
import time

class Execvesnoop:
    def __init__(self, args):
        self.args = args
        self.b = None
        self.initial_ts = 0
        self.setup_bpf()
        self.setup_perf_buffer()

    def setup_bpf(self):
        # define BPF program
        bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>
#include <bcc/proto.h>

#define ARGSIZE 128
#define MAXARG 60

struct val_t {
    u64 id;
    char comm[TASK_COMM_LEN];
    char filename[NAME_MAX];
    char argv[ARGSIZE];
};

struct data_t {
    u64 id;
    u64 ts;
    u32 uid;
    int ret;
    char comm[TASK_COMM_LEN];
    char filename[NAME_MAX];
    char argv[ARGSIZE];
};

BPF_PERCPU_ARRAY(tmp_storage, struct val_t, 1);
BPF_PERCPU_ARRAY(tmp_data, struct data_t, 1);
BPF_PERF_OUTPUT(events);

int trace_execve_return(struct pt_regs *ctx, const char __user *filename,
    const char __user *const __user *argv, int ret)
{
    struct val_t *valp;
    struct data_t *datap;
    u64 id;
    u32 pid;
    u32 tid;
    u32 uid;
    u64 tsp;
    int zero;

    zero = 0;
    id = bpf_get_current_pid_tgid();
    pid = id >> 32;
    tid = id;
    uid = bpf_get_current_uid_gid();
    tsp = bpf_ktime_get_ns();

    PID_TID_FILTER
    UID_FILTER

    valp = tmp_storage.lookup(&zero);
    if (!valp)
        return 0;

    bpf_probe_read_str(&valp->filename, sizeof(valp->filename), filename);
    bpf_probe_read_str(&valp->argv, sizeof(valp->argv), argv);

    datap = tmp_data.lookup(&zero);
    if (!datap)
        return 0;

    datap->id = id;
    datap->ts = tsp / 1000;
    datap->uid = uid;
    datap->ret = ret;
    bpf_get_current_comm(&datap->comm, sizeof(datap->comm));
    bpf_probe_read_kernel(&datap->filename, sizeof(datap->filename), valp->filename);
    bpf_probe_read_kernel(&datap->argv, sizeof(datap->argv), valp->argv);
    events.perf_submit(ctx, datap, sizeof(struct data_t));
    return 0;
}
"""
        b = BPF(text='')
        fnname_execve = b.get_syscall_prefix().decode() + 'execve'
        bpf_text = bpf_text % ()  # no interval needed in BPF now
        if self.args.tid:  # TID trumps PID
            bpf_text = bpf_text.replace('PID_TID_FILTER',
                'if (tid != %s) { return 0; }' % self.args.tid)
        elif self.args.pid:
            bpf_text = bpf_text.replace('PID_TID_FILTER',
                'if (pid != %s) { return 0; }' % self.args.pid)
        else:
            bpf_text = bpf_text.replace('PID_TID_FILTER', '')
        if self.args.uid:
            bpf_text = bpf_text.replace('UID_FILTER',
                'if (uid != %s) { return 0; }' % self.args.uid)
        else:
            bpf_text = bpf_text.replace('UID_FILTER', '')
        if hasattr(self.args, 'debug') and self.args.debug or getattr(self.args, 'ebpf', False):
            print(bpf_text)
            if getattr(self.args, 'ebpf', False):
                exit()
        self.b = BPF(text=bpf_text)
        self.b.attach_kretprobe(event=fnname_execve, fn_name="trace_execve_return")

    def setup_perf_buffer(self):
        # Define the data_t struct in Python for perf buffer parsing
        class Data(ctypes.Structure):
            _fields_ = [
                ("id", ctypes.c_ulonglong),
                ("ts", ctypes.c_ulonglong),
                ("uid", ctypes.c_uint),
                ("ret", ctypes.c_int),
                ("comm", ctypes.c_char * 16),
                ("filename", ctypes.c_char * 255),
                ("argv", ctypes.c_char * 128),
            ]

        # header
        # Always show timestamp and UID regardless of flags
        print("%-24s" % ("TIMESTAMP"), end="")
        print("%-6s" % ("UID"), end="")
        print("%-6s %-16s %-8s %s" % 
              ("TID" if self.args.tid else "PID", "COMM", "RET", "ARGS"))

        # Фильтрация повторов по интервалу, имени и argv
        self.last_events = {}
        self.interval_ns = self.args.interval * 1_000_000_000
        self.boot_time = self.get_boot_time()

        def print_event(cpu, data, size):
            event = ctypes.cast(data, ctypes.POINTER(Data)).contents
            if not self.initial_ts:
                self.initial_ts = event.ts
            skip = False
            if self.args.failed and (event.ret >= 0):
                skip = True
            if self.args.name and bytes(self.args.name) not in event.comm:
                skip = True
            # --- фильтрация повторов ---
            pid = event.id >> 32
            now = event.ts * 1000  # event.ts is in us, convert to ns
            key = (pid, event.filename[:], event.argv[:])
            last = self.last_events.get(key)
            if last:
                last_ts = last
                if (now - last_ts) < self.interval_ns:
                    skip = True
            if not skip:
                self.last_events[key] = now
                # Convert timestamp to datetime format
                ts_seconds = event.ts / 1000000  # Convert microseconds to seconds
                real_time = self.boot_time + ts_seconds
                dt = datetime.fromtimestamp(real_time)
                timestamp_str = dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                
                # Display datetime timestamp instead of relative seconds
                printb(b"%-24s" % timestamp_str.encode(), nl="")
                printb(b"%-6d" % event.uid, nl="")
                printb(b"%-6d %-16s %-8d %s" % 
                      (event.id & 0xffffffff if self.args.tid else event.id >> 32,
                       event.comm,
                       event.ret,
                       event.argv))

        self.b["events"].open_perf_buffer(print_event, page_cnt=self.args.buffer_pages)

    def get_boot_time(self):
        """Get system boot time to calculate real timestamps"""
        try:
            with open('/proc/stat') as f:
                for line in f:
                    if line.startswith('btime'):
                        return float(line.strip().split()[1])
        except:
            # Fallback to current time if we can't get boot time
            return time.time()
        return time.time()

    def run(self):
        from datetime import datetime
        start_time = datetime.now()
        while not self.args.duration or datetime.now() - start_time < self.args.duration:
            try:
                self.b.perf_buffer_poll()
            except KeyboardInterrupt:
                break

    def cleanup(self):
        if self.b:
            self.b.cleanup()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-T", "--timestamp", action="store_true")
    parser.add_argument("-U", "--print-uid", action="store_true")
    parser.add_argument("-x", "--failed", action="store_true")
    parser.add_argument("-p", "--pid")
    parser.add_argument("-t", "--tid")
    parser.add_argument("--cgroupmap")
    parser.add_argument("--mntnsmap")
    parser.add_argument("-u", "--uid")
    parser.add_argument("-d", "--duration")
    parser.add_argument("-n", "--name", type=str)
    parser.add_argument("-e", "--extended_fields", action="store_true")
    parser.add_argument("-b", "--buffer-pages", type=int, default=64)
    parser.add_argument("-i", "--interval", type=int, default=2)
    args = parser.parse_args()
    if args.duration:
        from datetime import timedelta
        args.duration = timedelta(seconds=int(args.duration))
    monitor = Execvesnoop(args)
    try:
        monitor.run()
    except KeyboardInterrupt:
        pass
    finally:
        monitor.cleanup()

if __name__ == "__main__":
    main() 