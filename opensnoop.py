#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# opensnoop Trace open() syscalls.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: opensnoop [-h] [-T] [-U] [-x] [-p PID] [-t TID]
#                  [--cgroupmap CGROUPMAP] [--mntnsmap MNTNSMAP] [-u UID]
#                  [-d DURATION] [-n NAME] [-F] [-e] [-f FLAG_FILTER]
#                  [-b BUFFER_PAGES]
#

from __future__ import print_function
from bcc import ArgString, BPF
from bcc.containers import filter_by_containers
from bcc.utils import printb
import argparse
from collections import defaultdict
from datetime import datetime, timedelta
import os
import ctypes
import time

def parse_args():
    parser = argparse.ArgumentParser(
        description="Trace open() syscalls",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-T", "--timestamp", action="store_true",
        help="include timestamp on output")
    parser.add_argument("-U", "--print-uid", action="store_true",
        help="print UID column")
    parser.add_argument("-x", "--failed", action="store_true",
        help="only show failed opens")
    parser.add_argument("-p", "--pid",
        help="trace this PID only")
    parser.add_argument("-t", "--tid",
        help="trace this TID only")
    parser.add_argument("--cgroupmap",
        help="trace cgroups in this BPF map")
    parser.add_argument("--mntnsmap",
        help="trace mount namespaces in this BPF map")
    parser.add_argument("-u", "--uid",
        help="trace this UID only")
    parser.add_argument("-d", "--duration",
        help="total duration of trace in seconds")
    parser.add_argument("-n", "--name",
        help="only print process names containing this name")
    parser.add_argument("-F", "--full-path", action="store_true",
        help="show full path for an open file")
    parser.add_argument("-e", "--extended_fields", action="store_true",
        help="show extended fields")
    parser.add_argument("-f", "--flag-filter",
        help="filter by open flags")
    parser.add_argument("-b", "--buffer-pages", default=1024, type=int,
        help="number of BPF ring buffer pages, default 1024")
    parser.add_argument("--ebpf", action="store_true", help="print the generated BPF program and exit")
    return parser.parse_args()

class Opensnoop:
    def __init__(self, args):
        self.args = args
        self.b = None
        self.initial_ts = 0
        self.entries = defaultdict(list)
        self.setup_bpf()
        self.setup_perf_buffer()

    def setup_bpf(self):
        from bcc import BPF
        args = self.args
        bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/fcntl.h>
#include <linux/sched.h>
#ifdef FULLPATH
#include <linux/fs_struct.h>
#include <linux/dcache.h>
#define MAX_ENTRIES 32
enum event_type {
    EVENT_ENTRY,
    EVENT_END,
};
#endif
struct val_t {
    u64 id;
    char comm[TASK_COMM_LEN];
    const char *fname;
    int flags; // EXTENDED_STRUCT_MEMBER
    u32 mode; // EXTENDED_STRUCT_MEMBER
};
struct data_t {
    u64 id;
    u64 ts;
    u32 uid;
    int ret;
    char comm[TASK_COMM_LEN];
#ifdef FULLPATH
    enum event_type type;
#endif
    char name[NAME_MAX];
    int flags; // EXTENDED_STRUCT_MEMBER
    u32 mode; // EXTENDED_STRUCT_MEMBER
};
BPF_PERF_OUTPUT(events);
"""
        bpf_text_kprobe = """
BPF_HASH(infotmp, u64, struct val_t);
int trace_return(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct val_t *valp;
    struct data_t data = {};
    u64 tsp = bpf_ktime_get_ns();
    valp = infotmp.lookup(&id);
    if (valp == 0) {
        // пропущенная запись
        return 0;
    }
    bpf_probe_read_kernel(&data.comm, sizeof(data.comm), valp->comm);
    bpf_probe_read_user_str(&data.name, sizeof(data.name), (void *)valp->fname);
    data.id = valp->id;
    data.ts = tsp / 1000;
    data.uid = bpf_get_current_uid_gid();
    data.flags = valp->flags; // EXTENDED_STRUCT_MEMBER
    data.mode = valp->mode; // EXTENDED_STRUCT_MEMBER
    data.ret = PT_REGS_RC(ctx);
    SUBMIT_DATA
    infotmp.delete(&id);
    return 0;
}
"""
        bpf_text_kprobe_header_open = """
int syscall__trace_entry_open(struct pt_regs *ctx, const char __user *filename,
                              int flags, u32 mode)
{
"""
        bpf_text_kprobe_header_openat = """
int syscall__trace_entry_openat(struct pt_regs *ctx, int dfd,
                                const char __user *filename, int flags,
                                u32 mode)
{
"""
        bpf_text_kprobe_header_openat2 = """
#include <uapi/linux/openat2.h>
int syscall__trace_entry_openat2(struct pt_regs *ctx, int dfd, const char __user *filename, struct open_how *how)
{
    int flags = how->flags;
    u32 mode = 0;
    if (flags & O_CREAT || (flags & O_TMPFILE) == O_TMPFILE)
        mode = how->mode;
"""
        bpf_text_kprobe_body = """
    struct val_t val = {};
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID - старшая часть
    u32 tid = id;       // Приведение типа и получение младшей части
    u32 uid = bpf_get_current_uid_gid();
    PID_TID_FILTER
    UID_FILTER
    FLAGS_FILTER
    if (container_should_be_filtered()) {
        return 0;
    }
    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
        val.id = id;
        val.fname = filename;
        val.flags = flags; // EXTENDED_STRUCT_MEMBER
        val.mode = mode; // EXTENDED_STRUCT_MEMBER
        infotmp.update(&id, &val);
    }
    return 0;
};
"""
        bpf_text_kfunc_header_open = """
#if defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER) && !defined(__s390x__)
KRETFUNC_PROBE(FNNAME, struct pt_regs *regs, int ret)
{
    const char __user *filename = (char *)PT_REGS_PARM1(regs);
    int flags = PT_REGS_PARM2(regs);
    u32 mode = 0;
    if (flags & O_CREAT || (flags & O_TMPFILE) == O_TMPFILE)
        mode = PT_REGS_PARM3(regs);
#else
KRETFUNC_PROBE(FNNAME, const char __user *filename, int flags,
               u32 mode, int ret)
{
#endif
"""
        bpf_text_kfunc_header_openat = """
#if defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER) && !defined(__s390x__)
KRETFUNC_PROBE(FNNAME, struct pt_regs *regs, int ret)
{
    int dfd = PT_REGS_PARM1(regs);
    const char __user *filename = (char *)PT_REGS_PARM2(regs);
    int flags = PT_REGS_PARM3(regs);
    u32 mode = 0;
    if (flags & O_CREAT || (flags & O_TMPFILE) == O_TMPFILE)
        mode = PT_REGS_PARM4(regs);
#else
KRETFUNC_PROBE(FNNAME, int dfd, const char __user *filename, int flags,
               u32 mode, int ret)
{
#endif
"""
        bpf_text_kfunc_header_openat2 = """
#include <uapi/linux/openat2.h>
#if defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER) && !defined(__s390x__)
KRETFUNC_PROBE(FNNAME, struct pt_regs *regs, int ret)
{
    int dfd = PT_REGS_PARM1(regs);
    const char __user *filename = (char *)PT_REGS_PARM2(regs);
    struct open_how __user how;
    int flags;
    u32 mode = 0;
    bpf_probe_read_user(&how, sizeof(struct open_how), (struct open_how*)PT_REGS_PARM3(regs));
    flags = how.flags;
    if (flags & O_CREAT || (flags & O_TMPFILE) == O_TMPFILE)
        mode = how.mode;
#else
KRETFUNC_PROBE(FNNAME, int dfd, const char __user *filename, struct open_how __user *how, int ret)
{
    int flags = how->flags;
    u32 mode = 0;
    if (flags & O_CREAT || (flags & O_TMPFILE) == O_TMPFILE)
        mode = how->mode;
#endif
"""
        bpf_text_kfunc_body = """
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID - старшая часть
    u32 tid = id;       // Приведение типа и получение младшей части
    u32 uid = bpf_get_current_uid_gid();
    PID_TID_FILTER
    UID_FILTER
    FLAGS_FILTER
    if (container_should_be_filtered()) {
        return 0;
    }
    struct data_t data = {};
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    u64 tsp = bpf_ktime_get_ns();
    bpf_probe_read_user_str(&data.name, sizeof(data.name), (void *)filename);
    data.id    = id;
    data.ts    = tsp / 1000;
    data.uid   = bpf_get_current_uid_gid();
    data.flags = flags; // EXTENDED_STRUCT_MEMBER
    data.mode  = mode; // EXTENDED_STRUCT_MEMBER
    data.ret   = ret;
    SUBMIT_DATA
    return 0;
}
"""
        b = BPF(text='')
        fnname_open = b.get_syscall_prefix().decode() + 'open'
        fnname_openat = b.get_syscall_prefix().decode() + 'openat'
        fnname_openat2 = b.get_syscall_prefix().decode() + 'openat2'
        if b.ksymname(fnname_openat2) == -1:
            fnname_openat2 = None
        if getattr(args, 'full_path', False):
            bpf_text = "#define FULLPATH\n" + bpf_text
        is_support_kfunc = BPF.support_kfunc()
        if is_support_kfunc:
            bpf_text += bpf_text_kfunc_header_open.replace('FNNAME', fnname_open)
            bpf_text += bpf_text_kfunc_body
            bpf_text += bpf_text_kfunc_header_openat.replace('FNNAME', fnname_openat)
            bpf_text += bpf_text_kfunc_body
            if fnname_openat2:
                bpf_text += bpf_text_kfunc_header_openat2.replace('FNNAME', fnname_openat2)
                bpf_text += bpf_text_kfunc_body
        else:
            bpf_text += bpf_text_kprobe
            bpf_text += bpf_text_kprobe_header_open
            bpf_text += bpf_text_kprobe_body
            bpf_text += bpf_text_kprobe_header_openat
            bpf_text += bpf_text_kprobe_body
            if fnname_openat2:
                bpf_text += bpf_text_kprobe_header_openat2
                bpf_text += bpf_text_kprobe_body
        if getattr(args, 'tid', None):
            bpf_text = bpf_text.replace('PID_TID_FILTER',
                f'if (tid != {args.tid}) {{ return 0; }}')
        elif getattr(args, 'pid', None):
            bpf_text = bpf_text.replace('PID_TID_FILTER',
                f'if (pid != {args.pid}) {{ return 0; }}')
        else:
            bpf_text = bpf_text.replace('PID_TID_FILTER', '')
        if getattr(args, 'uid', None):
            bpf_text = bpf_text.replace('UID_FILTER',
                f'if (uid != {args.uid}) {{ return 0; }}')
        else:
            bpf_text = bpf_text.replace('UID_FILTER', '')
        bpf_text = filter_by_containers(args) + bpf_text
        if getattr(args, 'flag_filter', None):
            bpf_text = bpf_text.replace('FLAGS_FILTER',
                f'if (!(flags & {args.flag_filter})) {{ return 0; }}')
        else:
            bpf_text = bpf_text.replace('FLAGS_FILTER', '')
        if not (getattr(args, 'extended_fields', False) or getattr(args, 'flag_filter', None)):
            bpf_text = '\n'.join(x for x in bpf_text.split('\n')
                if 'EXTENDED_STRUCT_MEMBER' not in x)
        if getattr(args, 'full_path', False):
            bpf_text = bpf_text.replace('SUBMIT_DATA', """
    data.type = EVENT_ENTRY;
    events.perf_submit(ctx, &data, sizeof(data));
    if (data.name[0] != '/') { // относительный путь
        struct task_struct *task;
        struct dentry *dentry;
        int i;
        task = (struct task_struct *)bpf_get_current_task_btf();
        dentry = task->fs->pwd.dentry;
        for (i = 1; i < MAX_ENTRIES; i++) {
            bpf_probe_read_kernel(&data.name, sizeof(data.name), (void *)dentry->d_name.name);
            data.type = EVENT_ENTRY;
            events.perf_submit(ctx, &data, sizeof(data));
            if (dentry == dentry->d_parent) { // корневой каталог
                break;
            }
            dentry = dentry->d_parent;
        }
    }
    data.type = EVENT_END;
    events.perf_submit(ctx, &data, sizeof(data));
    """)
        else:
            bpf_text = bpf_text.replace('SUBMIT_DATA', """
    events.perf_submit(ctx, &data, sizeof(data));
    """)
        if getattr(args, 'ebpf', False):
            print(bpf_text)
            if args.ebpf:
                exit()
        self.b = BPF(text=bpf_text)
        if not is_support_kfunc:
            self.b.attach_kprobe(event=fnname_open, fn_name="syscall__trace_entry_open")
            self.b.attach_kretprobe(event=fnname_open, fn_name="trace_return")
            self.b.attach_kprobe(event=fnname_openat, fn_name="syscall__trace_entry_openat")
            self.b.attach_kretprobe(event=fnname_openat, fn_name="trace_return")
            if fnname_openat2:
                self.b.attach_kprobe(event=fnname_openat2, fn_name="syscall__trace_entry_openat2")
                self.b.attach_kretprobe(event=fnname_openat2, fn_name="trace_return")

    def setup_perf_buffer(self):
        args = self.args
        b = self.b
        self.initial_ts = 0
        self.entries = defaultdict(list)
        self.boot_time = self.get_boot_time()
        
        # заголовок
        # Всегда показывать метку времени и UID независимо от флагов
        print("%-24s" % ("TIMESTAMP"), end="")
        print("%-6s" % ("UID"), end="")
        print("%-6s %-16s %4s %3s " %
              ("TID" if getattr(args, 'tid', None) else "PID", "COMM", "FD", "ERR"), end="")
        if getattr(args, 'extended_fields', False):
            print("%-8s %-4s " % ("FLAGS", "MODE"), end="")
        print("PATH")
        class EventType:
            EVENT_ENTRY = 0
            EVENT_END = 1
        self.EventType = EventType

        def print_event(cpu, data, size):
            event = b["events"].event(data)
            if not getattr(args, 'full_path', False) or event.type == EventType.EVENT_END:
                skip = False
                if event.ret >= 0:
                    fd_s = event.ret
                    err = 0
                else:
                    fd_s = -1
                    err = - event.ret
                if not self.initial_ts:
                    self.initial_ts = event.ts
                if getattr(args, 'failed', False) and (event.ret >= 0):
                    skip = True
                if getattr(args, 'name', None) and bytes(args.name) not in event.comm:
                    skip = True
                if not skip:
                    # Преобразование метки времени в формат datetime
                    ts_seconds = event.ts / 1000000  # Преобразование микросекунд в секунды
                    real_time = self.boot_time + ts_seconds
                    dt = datetime.fromtimestamp(real_time)
                    timestamp_str = dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                    
                    # Отображение метки времени в формате datetime вместо относительных секунд
                    printb(b"%-24s" % timestamp_str.encode(), nl="")
                    printb(b"%-6d" % event.uid, nl="")
                    printb(b"%-6d %-16s %4d %3d " %
                           (event.id & 0xffffffff if getattr(args, 'tid', None) else event.id >> 32,
                            event.comm, fd_s, err), nl="")
                    if getattr(args, 'extended_fields', False):
                        if event.mode == 0 and event.flags & os.O_CREAT == 0 and \
                           (event.flags & os.O_TMPFILE) != os.O_TMPFILE:
                            printb(b"%08o n/a  " % event.flags, nl="")
                        else:
                            printb(b"%08o %04o " % (event.flags, event.mode), nl="")
                    if not getattr(args, 'full_path', False):
                        printb(b"%s" % event.name)
                    else:
                        paths = self.entries[event.id]
                        paths.reverse()
                        printb(b"%s" % os.path.join(*paths))
                if getattr(args, 'full_path', False):
                    try:
                        del(self.entries[event.id])
                    except Exception:
                        pass
            elif event.type == EventType.EVENT_ENTRY:
                self.entries[event.id].append(event.name)

        self.b["events"].open_perf_buffer(print_event, page_cnt=getattr(args, 'buffer_pages', 1024))

    def get_boot_time(self):
        """Получить время загрузки системы для расчета реальных меток времени"""
        try:
            with open('/proc/stat') as f:
                for line in f:
                    if line.startswith('btime'):
                        return float(line.strip().split()[1])
        except:
            # Возврат текущего времени, если не удалось получить время загрузки
            return time.time()
        return time.time()

    def run(self):
        from datetime import datetime
        args = self.args
        start_time = datetime.now()
        while not getattr(args, 'duration', None) or datetime.now() - start_time < args.duration:
            try:
                self.b.perf_buffer_poll()
            except KeyboardInterrupt:
                break
    def cleanup(self):
        if self.b:
            self.b.cleanup()

if __name__ == "__main__":
    args = parse_args()
    if args.duration:
        args.duration = timedelta(seconds=int(args.duration))
    opensnoop = Opensnoop(args)
    try:
        opensnoop.run()
    except KeyboardInterrupt:
        pass
