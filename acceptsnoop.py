#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# acceptsnoop Trace accept() syscalls.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: acceptsnoop [-h] [-T] [-U] [-x] [-p PID] [-t TID]
#                  [--cgroupmap CGROUPMAP] [--mntnsmap MNTNSMAP] [-u UID]
#                  [-d DURATION] [-n NAME] [-e] [-b BUFFER_PAGES] [-i INTERVAL]


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

class Acceptsnoop:
    def __init__(self, args):
        self.args = args
        self.b = None
        self.initial_ts = 0
        self.setup_bpf()
        self.setup_perf_buffer()

    def setup_bpf(self):
        # определение BPF программы
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
        };

        struct data_t {
            u64 id;
            u64 ts;
            u32 uid;
            int ret;
            char comm[TASK_COMM_LEN];
            u16 sport;
            u16 dport;
            u32 saddr;
            u32 daddr;
        };

        // Добавление структуры отслеживания для фильтрации
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
        // пропущенная запись
        return 0;
    }

    // Проверка успешности accept
    int ret = PT_REGS_RC(ctx);
    if (ret < 0) {
        infotmp.delete(&id);
        return 0;
    }

    // Получение информации о сокете
    struct sock *sk = (struct sock *)ret;
    if (sk == NULL) {
        infotmp.delete(&id);
        return 0;
    }

    // Чтение информации о сокете
    u16 sport = 0, dport = 0;
    u32 saddr = 0, daddr = 0;
    
    // Получение исходных и целевых портов
    bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    sport = bpf_ntohs(sport);
    dport = bpf_ntohs(dport);
    
    // Получение исходных и целевых адресов
    bpf_probe_read_kernel(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);

    // Проверка, следует ли фильтровать это событие
    last_event = last_events.lookup(&pid);
    if (last_event != 0) {
        // Обновление статистики
        last_event->event_count++;
        
        // Показывать только если:
        // 1. Прошло больше FILTER_INTERVAL секунд с момента последнего события
        // 2. Другой исходный порт
        // 3. Другой целевой порт
        // 4. Другой исходный адрес
        // 5. Другой целевой адрес
        if ((tsp - last_event->last_ts) < FILTER_INTERVAL_NS &&
            last_event->last_sport == sport &&
            last_event->last_dport == dport &&
            last_event->last_saddr == saddr &&
            last_event->last_daddr == daddr) {
            infotmp.delete(&id);
            return 0;
        }
    }

    // Обновление информации о последнем событии
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
        bpf_text_kprobe_header_accept = """
int syscall__trace_entry_accept4(struct pt_regs *ctx, int fd, struct sockaddr *addr, int *addrlen, int flags)
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
        infotmp.update(&id, &val);
    }

    return 0;
};
"""
        bpf_text_kfunc_header_accept = """
#if defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER) && !defined(__s390x__)
KRETFUNC_PROBE(FNNAME, struct pt_regs *regs, int ret)
{
    int fd = PT_REGS_PARM1(regs);
    struct sockaddr *addr = (struct sockaddr *)PT_REGS_PARM2(regs);
    int *addrlen = (int *)PT_REGS_PARM3(regs);
    int flags = PT_REGS_PARM4(regs);
#else
KRETFUNC_PROBE(FNNAME, int fd, struct sockaddr *addr, int *addrlen, int flags, int ret)
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

    // Проверка успешности accept
    if (ret < 0) {
        return 0;
    }

    // Получение информации о сокете
    struct sock *sk = (struct sock *)ret;
    if (sk == NULL) {
        return 0;
    }

    // Чтение информации о сокете
    u16 sport = 0, dport = 0;
    u32 saddr = 0, daddr = 0;
    
    // Получение исходных и целевых портов
    bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    sport = bpf_ntohs(sport);
    dport = bpf_ntohs(dport);
    
    // Получение исходных и целевых адресов
    bpf_probe_read_kernel(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);

    // Проверка, следует ли фильтровать это событие
    last_event = last_events.lookup(&pid);
    if (last_event != 0) {
        // Обновление статистики
        last_event->event_count++;
        
        // Показывать только если:
        // 1. Прошло больше FILTER_INTERVAL секунд с момента последнего события
        // 2. Другой исходный порт
        // 3. Другой целевой порт
        // 4. Другой исходный адрес
        // 5. Другой целевой адрес
        if ((tsp - last_event->last_ts) < FILTER_INTERVAL_NS &&
            last_event->last_sport == sport &&
            last_event->last_dport == dport &&
            last_event->last_saddr == saddr &&
            last_event->last_daddr == daddr) {
            return 0;
        }
    }

    // Обновление информации о последнем событии
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
        fnname_accept = b.get_syscall_prefix().decode() + 'accept4'
        filter_interval_ns = self.args.interval * 1000000000
        bpf_text = bpf_text % filter_interval_ns
        is_support_kfunc = BPF.support_kfunc()
        if is_support_kfunc:
            bpf_text += bpf_text_kfunc_header_accept.replace('FNNAME', fnname_accept)
            bpf_text += bpf_text_kfunc_body
        else:
            bpf_text += bpf_text_kprobe
            bpf_text += bpf_text_kprobe_header_accept
            bpf_text += bpf_text_kprobe_body
        if self.args.tid:  # TID имеет приоритет перед PID
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
            self.b.attach_kprobe(event=fnname_accept, fn_name="syscall__trace_entry_accept4")
            self.b.attach_kretprobe(event=fnname_accept, fn_name="trace_return")

    def setup_perf_buffer(self):
        # Определение структуры data_t в Python для анализа буфера perf
        class Data(ctypes.Structure):
            _fields_ = [
                ("id", ctypes.c_ulonglong),
                ("ts", ctypes.c_ulonglong),
                ("uid", ctypes.c_uint),
                ("ret", ctypes.c_int),
                ("comm", ctypes.c_char * 16),
                ("sport", ctypes.c_ushort),
                ("dport", ctypes.c_ushort),
                ("saddr", ctypes.c_uint),
                ("daddr", ctypes.c_uint),
            ]

        # Получение времени загрузки системы для расчета меток времени
        self.boot_time = self.get_boot_time()

        # заголовок
        # Всегда показывать метку времени и UID независимо от флагов
        print("%-24s" % ("TIMESTAMP"), end="")
        print("%-6s" % ("UID"), end="")
        print("%-6s %-16s %-15s %-6s %-15s %-6s %s" % 
              ("TID" if self.args.tid else "PID", "COMM", "SADDR", "SPORT", "DADDR", "DPORT", "RET"))

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
                # Преобразование IP-адресов в строковый формат
                saddr_str = socket.inet_ntoa(struct.pack("I", event.saddr))
                daddr_str = socket.inet_ntoa(struct.pack("I", event.daddr))

                # Преобразование метки времени в формат datetime
                ts_seconds = event.ts / 1000000  # Преобразование микросекунд в секунды
                real_time = self.boot_time + ts_seconds
                dt = datetime.fromtimestamp(real_time)
                timestamp_str = dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                
                # Отображение метки времени в формате datetime вместо относительных секунд
                printb(b"%-24s" % timestamp_str.encode(), nl="")
                printb(b"%-6d" % event.uid, nl="")
                printb(b"%-6d %-16s %-15s %-6d %-15s %-6d %d" % 
                      (event.id & 0xffffffff if self.args.tid else event.id >> 32,
                       event.comm,
                       saddr_str.encode(),
                       event.sport,
                       daddr_str.encode(),
                       event.dport,
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
    monitor = Acceptsnoop(args)
    try:
        monitor.run()
    except KeyboardInterrupt:
        pass
    finally:
        monitor.cleanup()

if __name__ == "__main__":
    main() 