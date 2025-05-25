#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# recvfromsnoop Trace recvfrom() syscalls.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: recvfromsnoop [-h] [-T] [-U] [-x] [-p PID] [-t TID]
#                  [--cgroupmap CGROUPMAP] [--mntnsmap MNTNSMAP] [-u UID]
#                  [-d DURATION] [-n NAME] [-e] [-b BUFFER_PAGES] [-i INTERVAL]
#
# Copyright (c) 2024
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import ArgString, BPF
from bcc.containers import filter_by_containers
from bcc.utils import printb
import argparse
from collections import defaultdict
from datetime import datetime, timedelta
import os
import ctypes
import signal
import socket
import struct
import time

class Recvfromsnoop:
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
        #include <net/sock.h>
        #include <bcc/proto.h>

        #define FILTER_INTERVAL_NS %d

        struct val_t {
            u64 id;
            char comm[TASK_COMM_LEN];
            int fd;
            size_t size;
        };

        struct data_t {
            u64 id;
            u64 ts;
            u32 uid;
            int ret;
            char comm[TASK_COMM_LEN];
            int fd;
            size_t size;
            u16 sport;
            u16 dport;
            u32 saddr;
            u32 daddr;
        };

        // Add tracking structure for filtering
        struct last_event_t {
            u64 last_ts;
            u16 last_sport;
            u16 last_dport;
            u32 last_saddr;
            u32 last_daddr;
            u32 event_count;
        };

        BPF_PERF_OUTPUT(events);
        BPF_HASH(infotmp, u64, struct val_t);
        BPF_HASH(last_events, u32, struct last_event_t);
        """
        bpf_text_kprobe = """
BPF_HASH(infotmp, u64, struct val_t);

int trace_return(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct val_t *valp;
    struct data_t data = {};
    u32 pid = id >> 32;
    struct last_event_t *last_event;
    u64 tsp = bpf_ktime_get_ns();

    valp = infotmp.lookup(&id);
    if (valp == 0) {
        // missed entry
        return 0;
    }

    // Check if recvfrom was successful
    int ret = PT_REGS_RC(ctx);
    if (ret < 0) {
        infotmp.delete(&id);
        return 0;
    }

    // Get socket information
    struct sock *sk = (struct sock *)valp->fd;
    if (sk == NULL) {
        infotmp.delete(&id);
        return 0;
    }

    // Read socket information
    u16 sport = 0, dport = 0;
    u32 saddr = 0, daddr = 0;
    
    // Get source and destination ports
    bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    sport = bpf_ntohs(sport);
    dport = bpf_ntohs(dport);
    
    // Get source and destination addresses
    bpf_probe_read_kernel(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);

    // Check if we should filter this event
    last_event = last_events.lookup(&pid);
    if (last_event != 0) {
        // Update statistics
        last_event->event_count++;
        
        // Only show if:
        // 1. More than FILTER_INTERVAL seconds has passed since last event
        // 2. Different source port
        // 3. Different destination port
        // 4. Different source address
        // 5. Different destination address
        if ((tsp - last_event->last_ts) < FILTER_INTERVAL_NS &&
            last_event->last_sport == sport &&
            last_event->last_dport == dport &&
            last_event->last_saddr == saddr &&
            last_event->last_daddr == daddr) {
            infotmp.delete(&id);
            return 0;
        }
    }

    // Update last event info
    struct last_event_t new_event = {};
    new_event.last_ts = tsp;
    new_event.last_sport = sport;
    new_event.last_dport = dport;
    new_event.last_saddr = saddr;
    new_event.last_daddr = daddr;
    new_event.event_count = 1;
    last_events.update(&pid, &new_event);

    bpf_probe_read_kernel(&data.comm, sizeof(data.comm), valp->comm);
    data.id = valp->id;
    data.ts = tsp / 1000;
    data.uid = bpf_get_current_uid_gid();
    data.fd = valp->fd;
    data.size = valp->size;
    data.sport = sport;
    data.dport = dport;
    data.saddr = saddr;
    data.daddr = daddr;
    data.ret = ret;

    events.perf_submit(ctx, &data, sizeof(data));

    infotmp.delete(&id);

    return 0;
}
"""
        bpf_text_kprobe_header_recvfrom = """
int syscall__trace_entry_recvfrom(struct pt_regs *ctx, int fd, void *buf, size_t size, int flags, struct sockaddr *src_addr, int *addrlen)
{
"""
        bpf_text_kprobe_body = """
    struct val_t val = {};
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part
    u32 tid = id;       // Cast and get the lower part
    u32 uid = bpf_get_current_uid_gid();

    PID_TID_FILTER
    UID_FILTER

    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
        val.id = id;
        val.fd = fd;
        val.size = size;
        infotmp.update(&id, &val);
    }

    return 0;
};
"""
        bpf_text_kfunc_header_recvfrom = """
#if defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER) && !defined(__s390x__)
KRETFUNC_PROBE(FNNAME, struct pt_regs *regs, int ret)
{
    int fd = PT_REGS_PARM1(regs);
    void *buf = (void *)PT_REGS_PARM2(regs);
    size_t size = (size_t)PT_REGS_PARM3(regs);
    int flags = (int)PT_REGS_PARM4(regs);
    struct sockaddr *src_addr = (struct sockaddr *)PT_REGS_PARM5(regs);
    int *addrlen = (int *)PT_REGS_PARM6(regs);
#else
KRETFUNC_PROBE(FNNAME, int fd, void *buf, size_t size, int flags, struct sockaddr *src_addr, int *addrlen, int ret)
{
#endif
"""
        bpf_text_kfunc_body = """
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part
    u32 tid = id;       // Cast and get the lower part
    u32 uid = bpf_get_current_uid_gid();
    struct last_event_t *last_event;
    u64 tsp = bpf_ktime_get_ns();

    PID_TID_FILTER
    UID_FILTER

    // Check if recvfrom was successful
    if (ret < 0) {
        return 0;
    }

    // Get socket information
    struct sock *sk = (struct sock *)fd;
    if (sk == NULL) {
        return 0;
    }

    // Read socket information
    u16 sport = 0, dport = 0;
    u32 saddr = 0, daddr = 0;
    
    // Get source and destination ports
    bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    sport = bpf_ntohs(sport);
    dport = bpf_ntohs(dport);
    
    // Get source and destination addresses
    bpf_probe_read_kernel(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);

    // Check if we should filter this event
    last_event = last_events.lookup(&pid);
    if (last_event != 0) {
        // Update statistics
        last_event->event_count++;
        
        // Only show if:
        // 1. More than FILTER_INTERVAL seconds has passed since last event
        // 2. Different source port
        // 3. Different destination port
        // 4. Different source address
        // 5. Different destination address
        if ((tsp - last_event->last_ts) < FILTER_INTERVAL_NS &&
            last_event->last_sport == sport &&
            last_event->last_dport == dport &&
            last_event->last_saddr == saddr &&
            last_event->last_daddr == daddr) {
            return 0;
        }
    }

    // Update last event info
    struct last_event_t new_event = {};
    new_event.last_ts = tsp;
    new_event.last_sport = sport;
    new_event.last_dport = dport;
    new_event.last_saddr = saddr;
    new_event.last_daddr = daddr;
    new_event.event_count = 1;
    last_events.update(&pid, &new_event);

    struct data_t data = {};
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    data.id    = id;
    data.ts    = tsp / 1000;
    data.uid   = bpf_get_current_uid_gid();
    data.fd    = fd;
    data.size  = size;
    data.sport = sport;
    data.dport = dport;
    data.saddr = saddr;
    data.daddr = daddr;
    data.ret   = ret;

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""
        b = BPF(text='')
        fnname_recvfrom = b.get_syscall_prefix().decode() + 'recvfrom'
        filter_interval_ns = self.args.interval * 1000000000
        bpf_text = bpf_text % filter_interval_ns
        is_support_kfunc = BPF.support_kfunc()
        if is_support_kfunc:
            bpf_text += bpf_text_kfunc_header_recvfrom.replace('FNNAME', fnname_recvfrom)
            bpf_text += bpf_text_kfunc_body
        else:
            bpf_text += bpf_text_kprobe
            bpf_text += bpf_text_kprobe_header_recvfrom
            bpf_text += bpf_text_kprobe_body
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
        if not is_support_kfunc:
            self.b.attach_kprobe(event=fnname_recvfrom, fn_name="syscall__trace_entry_recvfrom")
            self.b.attach_kretprobe(event=fnname_recvfrom, fn_name="trace_return")

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
                ("sport", ctypes.c_ushort),
                ("dport", ctypes.c_ushort),
                ("saddr", ctypes.c_uint),
                ("daddr", ctypes.c_uint),
            ]

        # Get system boot time for timestamp calculation
        self.boot_time = self.get_boot_time()

        # header
        # Always show timestamp and UID regardless of flags
        print("%-24s" % ("TIMESTAMP"), end="")
        print("%-6s" % ("UID"), end="")
        print("%-6s %-16s %-4s %-8s %-15s %-6s %-15s %-6s %s" % 
              ("TID" if self.args.tid else "PID", "COMM", "FD", "SIZE", "SADDR", "SPORT", "DADDR", "DPORT", "RET"))

        def print_event(cpu, data, size):
            event = ctypes.cast(data, ctypes.POINTER(Data)).contents
            if not self.initial_ts:
                self.initial_ts = event.ts
            skip = False
            if self.args.failed and (event.ret >= 0):
                skip = True
            if self.args.name and bytes(self.args.name) not in event.comm:
                skip = True
            if not skip:
                # Convert IP addresses to string format
                saddr_str = socket.inet_ntoa(struct.pack("I", event.saddr))
                daddr_str = socket.inet_ntoa(struct.pack("I", event.daddr))

                # Convert timestamp to datetime format
                ts_seconds = event.ts / 1000000  # Convert microseconds to seconds
                real_time = self.boot_time + ts_seconds
                dt = datetime.fromtimestamp(real_time)
                timestamp_str = dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                
                # Display datetime timestamp instead of relative seconds
                printb(b"%-24s" % timestamp_str.encode(), nl="")
                printb(b"%-6d" % event.uid, nl="")
                printb(b"%-6d %-16s %-4d %-8d %-15s %-6d %-15s %-6d %d" % 
                      (event.id & 0xffffffff if self.args.tid else event.id >> 32,
                       event.comm,
                       event.fd,
                       event.size,
                       saddr_str.encode(),
                       event.sport,
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
    monitor = Recvfromsnoop(args)
    try:
        monitor.run()
    except KeyboardInterrupt:
        pass
    finally:
        monitor.cleanup()

if __name__ == "__main__":
    main() 