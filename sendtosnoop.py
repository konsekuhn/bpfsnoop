#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# sendtosnoop Trace sendto() syscalls.
#            For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: sendtosnoop [-h] [-T] [-U] [-x] [-p PID] [-t TID]
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
import time
import ctypes
import socket
import struct

class Sendtosnoop:
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
#include <net/sock.h>
#include <net/inet_sock.h>

#define ARGSIZE 128
#define MAXARG 60
#define FILTER_INTERVAL_NS %d

struct val_t {
    u64 id;
    char comm[TASK_COMM_LEN];
    int fd;
    size_t size;
    u32 daddr;
    u16 dport;
};

struct data_t {
    u64 id;
    u64 ts;
    u32 uid;
    int ret;
    char comm[TASK_COMM_LEN];
    int fd;
    size_t size;
    u32 daddr;
    u16 dport;
};

BPF_HASH(infotmp, u64, struct val_t);
BPF_PERF_OUTPUT(events);

int trace_sendto_entry(struct pt_regs *ctx, int fd, void *buf, size_t len, int flags, struct sockaddr *addr, int addrlen) {
    u64 id = bpf_get_current_pid_tgid();
    struct val_t val = {};
    bpf_get_current_comm(&val.comm, sizeof(val.comm));
    val.id = id;
    val.fd = fd;
    val.size = len;
    if (addr != NULL && addrlen >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in sin = {};
        bpf_probe_read(&sin, sizeof(sin), addr);
        val.daddr = sin.sin_addr.s_addr;
        val.dport = ntohs(sin.sin_port);
    }
    infotmp.update(&id, &val);
    return 0;
}

int trace_sendto_return(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct val_t *valp = infotmp.lookup(&id);
    if (!valp)
        return 0;
    struct data_t data = {};
    data.id = valp->id;
    data.ts = bpf_ktime_get_ns() / 1000;
    data.uid = bpf_get_current_uid_gid();
    data.ret = PT_REGS_RC(ctx);
    __builtin_memcpy(&data.comm, valp->comm, sizeof(data.comm));
    data.fd = valp->fd;
    data.size = valp->size;
    data.daddr = valp->daddr;
    data.dport = valp->dport;
    events.perf_submit(ctx, &data, sizeof(data));
    infotmp.delete(&id);
    return 0;
}
"""
        b = BPF(text='')
        fnname_sendto = b.get_syscall_prefix().decode() + 'sendto'
        filter_interval_ns = self.args.interval * 1000000000
        bpf_text = bpf_text % filter_interval_ns
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
        self.b.attach_kprobe(event=fnname_sendto, fn_name="trace_sendto_entry")
        self.b.attach_kretprobe(event=fnname_sendto, fn_name="trace_sendto_return")

    def setup_perf_buffer(self):
        # Define the data_t struct in Python for perf buffer parsing
        class Data(ctypes.Structure):
            _fields_ = [
                ("id", ctypes.c_ulonglong),
                ("ts", ctypes.c_ulonglong),
                ("uid", ctypes.c_uint),
                ("ret", ctypes.c_int),
                ("comm", ctypes.c_char * 16),
                ("fd", ctypes.c_int),
                ("size", ctypes.c_ulonglong),
                ("daddr", ctypes.c_uint),
                ("dport", ctypes.c_ushort),
            ]

        # Get system boot time for timestamp calculation
        self.boot_time = self.get_boot_time()

        # header
        # Always show timestamp and UID regardless of flags
        print("%-24s" % ("TIMESTAMP"), end="")
        print("%-6s" % ("UID"), end="")
        print("%-6s %-16s %-4s %-8s %-15s %-6s %s" % 
              ("TID" if self.args.tid else "PID", "COMM", "FD", "SIZE", "ADDR", "PORT", "RET"))

        # Фильтрация повторов по (PID, fd, daddr, dport) и интервалу
        self.last_events = {}
        self.interval_ns = self.args.interval * 1_000_000_000

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
            now = event.ts * 1000  # event.ts в us, переводим в ns
            key = (pid, event.fd, event.daddr, event.dport)
            last = self.last_events.get(key)
            if last:
                last_ts = last
                if (now - last_ts) < self.interval_ns:
                    skip = True
            if not skip:
                self.last_events[key] = now
                # Convert IP address to string format
                daddr_str = socket.inet_ntoa(struct.pack("I", event.daddr))
                
                # Convert timestamp to datetime format
                ts_seconds = event.ts / 1000000  # Convert microseconds to seconds
                real_time = self.boot_time + ts_seconds
                dt = datetime.fromtimestamp(real_time)
                timestamp_str = dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                
                # Display datetime timestamp instead of relative seconds
                printb(b"%-24s" % timestamp_str.encode(), nl="")
                printb(b"%-6d" % event.uid, nl="")
                printb(b"%-6d %-16s %-4d %-8d %-15s %-6d %d" % 
                      (event.id & 0xffffffff if self.args.tid else event.id >> 32,
                       event.comm,
                       event.fd,
                       event.size,
                       daddr_str.encode(),
                       event.dport,
                       event.ret))

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
    monitor = Sendtosnoop(args)
    try:
        monitor.run()
    except KeyboardInterrupt:
        pass
    finally:
        monitor.cleanup()

if __name__ == "__main__":
    main() 