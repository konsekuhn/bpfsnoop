#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# readsnoop Trace read() syscalls.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: readsnoop [-h] [-T] [-U] [-x] [-p PID] [-t TID]
#                  [--cgroupmap CGROUPMAP] [--mntnsmap MNTNSMAP] [-u UID]
#                  [-d DURATION] [-n NAME] [-e] [-b BUFFER_PAGES] [-i INTERVAL]
#

from __future__ import print_function
from bcc import ArgString, BPF
from bcc.containers import filter_by_containers
from bcc.utils import printb
import argparse
from datetime import datetime, timedelta
import os
import ctypes
import time

class Readsnoop:
    def __init__(self, args):
        self.args = args
        self.b = None
        self.initial_ts = 0
        self.setup_bpf()
        self.setup_perf_buffer()

    def setup_bpf(self):
        from bcc import BPF
        # определение BPF программы
        bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>

#define FILTER_INTERVAL_NS %d

struct val_t {
    u64 id;
    char comm[TASK_COMM_LEN];
    int fd;
    u64 count;
};

struct data_t {
    u64 id;
    u64 ts;
    u32 uid;
    int ret;
    char comm[TASK_COMM_LEN];
    int fd;
    u64 count;
};

// Добавление структуры отслеживания для фильтрации
struct last_event_t {
    u64 last_ts;
    int last_fd;
    u64 last_count;
    u64 total_bytes;
    u32 event_count;
};

BPF_PERF_OUTPUT(events);
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
        // пропущенная запись
        return 0;
    }

    // Проверка, следует ли фильтровать это событие
    last_event = last_events.lookup(&pid);
    if (last_event != 0) {
        // Обновление статистики
        last_event->total_bytes += valp->count;
        last_event->event_count++;
        
        // Показывать только если:
        // 1. Прошло больше FILTER_INTERVAL секунд с момента последнего события
        // 2. Другой файловый дескриптор
        // 3. Другой размер чтения
        // 4. Или если мы накопили значительный объем данных
        if ((tsp - last_event->last_ts) < FILTER_INTERVAL_NS &&
            last_event->last_fd == valp->fd &&
            last_event->last_count == valp->count &&
            last_event->total_bytes < 1024 * 1024) { // порог в 1МБ
            infotmp.delete(&id);
            return 0;
        }
    }

    // Обновление информации о последнем событии
    struct last_event_t new_event = {};
    new_event.last_ts = tsp;
    new_event.last_fd = valp->fd;
    new_event.last_count = valp->count;
    new_event.total_bytes = valp->count;
    new_event.event_count = 1;
    last_events.update(&pid, &new_event);

    bpf_probe_read_kernel(&data.comm, sizeof(data.comm), valp->comm);
    data.id = valp->id;
    data.ts = tsp / 1000;
    data.uid = bpf_get_current_uid_gid();
    data.fd = valp->fd;
    data.count = valp->count;
    data.ret = PT_REGS_RC(ctx);

    events.perf_submit(ctx, &data, sizeof(data));

    infotmp.delete(&id);

    return 0;
}
"""
        bpf_text_kprobe_header_read = """
int syscall__trace_entry_read(struct pt_regs *ctx, int fd, void *buf, u64 count)
{
"""
        bpf_text_kprobe_body = """
    struct val_t val = {};
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID - старшая часть
    u32 tid = id;       // Приведение типа и получение младшей части
    u32 uid = bpf_get_current_uid_gid();

    PID_TID_FILTER
    UID_FILTER

    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
        val.id = id;
        val.fd = fd;
        val.count = count;
        infotmp.update(&id, &val);
    }

    return 0;
};
"""
        bpf_text_kfunc_header_read = """
#if defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER) && !defined(__s390x__)
KRETFUNC_PROBE(FNNAME, struct pt_regs *regs, int ret)
{
    int fd = PT_REGS_PARM1(regs);
    void *buf = (void *)PT_REGS_PARM2(regs);
    size_t count = PT_REGS_PARM3(regs);
#else
KRETFUNC_PROBE(FNNAME, int fd, void *buf, u64 count, int ret)
{
#endif
"""
        bpf_text_kfunc_body = """
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID - старшая часть
    u32 tid = id;       // Приведение типа и получение младшей части
    u32 uid = bpf_get_current_uid_gid();
    struct last_event_t *last_event;
    u64 tsp = bpf_ktime_get_ns();

    PID_TID_FILTER
    UID_FILTER

    // Проверка, следует ли фильтровать это событие
    last_event = last_events.lookup(&pid);
    if (last_event != 0) {
        // Обновление статистики
        last_event->total_bytes += count;
        last_event->event_count++;
        
        // Показывать только если:
        // 1. Прошло больше FILTER_INTERVAL секунд с момента последнего события
        // 2. Другой файловый дескриптор
        // 3. Другой размер чтения
        // 4. Или если мы накопили значительный объем данных
        if ((tsp - last_event->last_ts) < FILTER_INTERVAL_NS &&
            last_event->last_fd == fd &&
            last_event->last_count == count &&
            last_event->total_bytes < 1024 * 1024) { // порог в 1МБ
            return 0;
        }
    }

    // Обновление информации о последнем событии
    struct last_event_t new_event = {};
    new_event.last_ts = tsp;
    new_event.last_fd = fd;
    new_event.last_count = count;
    new_event.total_bytes = count;
    new_event.event_count = 1;
    last_events.update(&pid, &new_event);

    struct data_t data = {};
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    data.id    = id;
    data.ts    = tsp / 1000;
    data.uid   = bpf_get_current_uid_gid();
    data.fd    = fd;
    data.count = count;
    data.ret   = ret;

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""
        b = BPF(text='')
        fnname_read = b.get_syscall_prefix().decode() + 'read'
        filter_interval_ns = self.args.interval * 1000000000
        bpf_text = bpf_text % filter_interval_ns
        is_support_kfunc = BPF.support_kfunc()
        if is_support_kfunc:
            bpf_text += bpf_text_kfunc_header_read.replace('FNNAME', fnname_read)
            bpf_text += bpf_text_kfunc_body
        else:
            bpf_text += bpf_text_kprobe
            bpf_text += bpf_text_kprobe_header_read
            bpf_text += bpf_text_kprobe_body
        if self.args.tid:  # TID имеет приоритет перед PID
            bpf_text = bpf_text.replace('PID_TID_FILTER',
                f'if (tid != {self.args.tid}) {{ return 0; }}')
        elif self.args.pid:
            bpf_text = bpf_text.replace('PID_TID_FILTER',
                f'if (pid != {self.args.pid}) {{ return 0; }}')
        else:
            bpf_text = bpf_text.replace('PID_TID_FILTER', '')
        if self.args.uid:
            bpf_text = bpf_text.replace('UID_FILTER',
                f'if (uid != {self.args.uid}) {{ return 0; }}')
        else:
            bpf_text = bpf_text.replace('UID_FILTER', '')
        if hasattr(self.args, 'debug') and self.args.debug or getattr(self.args, 'ebpf', False):
            print(bpf_text)
            if getattr(self.args, 'ebpf', False):
                exit()
        self.b = BPF(text=bpf_text)
        if not is_support_kfunc:
            self.b.attach_kprobe(event=fnname_read, fn_name="syscall__trace_entry_read")
            self.b.attach_kretprobe(event=fnname_read, fn_name="trace_return")

    def setup_perf_buffer(self):
        # Определение структуры data_t в Python для анализа буфера perf
        class Data(ctypes.Structure):
            _fields_ = [
                ("id", ctypes.c_ulonglong),
                ("ts", ctypes.c_ulonglong),
                ("uid", ctypes.c_uint),
                ("ret", ctypes.c_int),
                ("comm", ctypes.c_char * 16),
                ("fd", ctypes.c_int),
                ("count", ctypes.c_ulonglong),
            ]

        # Получение времени загрузки системы для расчета меток времени
        self.boot_time = self.get_boot_time()

        # заголовок
        # Всегда показывать метку времени и UID независимо от флагов
        print("%-24s" % ("TIMESTAMP"), end="")
        print("%-6s" % ("UID"), end="")
        print("%-6s %-16s %4s %10s %6s" % 
              ("TID" if self.args.tid else "PID", "COMM", "FD", "BYTES", "RET"))

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
                # Преобразование метки времени в формат datetime
                ts_seconds = event.ts / 1000000  # Преобразование микросекунд в секунды
                real_time = self.boot_time + ts_seconds
                dt = datetime.fromtimestamp(real_time)
                timestamp_str = dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                
                # Отображение метки времени в формате datetime вместо относительных секунд
                printb(b"%-24s" % timestamp_str.encode(), nl="")
                printb(b"%-6d" % event.uid, nl="")
                printb(b"%-6d %-16s %4d %10d %6d" % 
                      (event.id & 0xffffffff if self.args.tid else event.id >> 32,
                       event.comm,
                       event.fd,
                       event.count,
                       event.ret))
        self.b["events"].open_perf_buffer(print_event, page_cnt=self.args.buffer_pages)

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
    parser = argparse.ArgumentParser(
        description="Trace read() syscalls",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-T", "--timestamp", action="store_true",
        help="include timestamp on output")
    parser.add_argument("-U", "--print-uid", action="store_true",
        help="print UID column")
    parser.add_argument("-x", "--failed", action="store_true",
        help="only show failed reads")
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
    parser.add_argument("-e", "--extended_fields", action="store_true",
        help="show extended fields")
    parser.add_argument("-b", "--buffer-pages", type=int, default=64,
        help="number of BPF ring buffer pages")
    parser.add_argument("-i", "--interval", type=int, default=1,
        help="rate-limit interval in seconds")
    parser.add_argument("--ebpf", action="store_true", help="print the generated BPF program and exit")
    args = parser.parse_args()
    if args.duration:
        from datetime import timedelta
        args.duration = timedelta(seconds=int(args.duration))
    readsnoop = Readsnoop(args)
    try:
        readsnoop.run()
    except KeyboardInterrupt:
        pass
    finally:
        readsnoop.cleanup()

if __name__ == "__main__":
    main() 