#!/usr/bin/env python3
# @lint-avoid-python-3-compatibility-imports
#
# syscall_monitor Universal system call monitor.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: syscall_monitor [-h] [-x] [-p PID] [-t TID]
#                  [--cgroupmap CGROUPMAP] [--mntnsmap MNTNSMAP] [-u UID]
#                  [-d DURATION] [-n NAME] [-e] [-b BUFFER_PAGES]
#                  [-s SYSCALLS] [--logfile LOGFILE]
#
# Copyright (c) 2024
# Licensed under the Apache License, Version 2.0 (the "License")

import os
import sys
import argparse
import subprocess
import time
import select
import fcntl
import threading
import queue
import datetime

# Dictionary of available syscall monitors
AVAILABLE_MONITORS = {
    'accept': 'acceptsnoop',
    'connect': 'connectsnoop',
    'execve': 'execvesnoop',
    'open': 'opensnoop',
    'read': 'readsnoop',
    'recvfrom': 'recvfromsnoop',
    'sendto': 'sendtosnoop',
    'write': 'writesnoop'
}

class OutputCollector:
    """
    Класс для сбора и обработки вывода от запущенных процессов
    """
    def __init__(self, logfile=None):
        self.logfile = logfile
        self.output_queue = queue.Queue()
        self.headers_shown = False
        self.running = True  # Инициализируем переменную до создания потока
        self.output_thread = threading.Thread(target=self._process_output, daemon=True)
        self.output_thread.start()
    
    def _process_output(self):
        """
        Обрабатывает вывод из очереди и выводит его в консоль и файл
        """
        while self.running:
            try:
                item = self.output_queue.get(timeout=0.1)
                if item is None:  # Сигнал завершения
                    break
                
                line, is_error = item
                
                # Если строка является заголовком (содержит "TIMESTAMP", "UID", "PID")
                if not self.headers_shown and "TIMESTAMP" in line and "UID" in line and "PID" in line:
                    print(line)
                    self.headers_shown = True
                    if self.logfile:
                        self.logfile.write(line + "\n")
                        self.logfile.flush()
                # Если строка не заголовок, или заголовки уже были показаны
                elif self.headers_shown or is_error or not any(keyword in line for keyword in ["TIMESTAMP", "UID", "PID"]):
                    if is_error:
                        print(f"ERROR: {line}", file=sys.stderr)
                        if self.logfile:
                            self.logfile.write(f"ERROR: {line}\n")
                            self.logfile.flush()
                    else:
                        print(line)
                        if self.logfile:
                            self.logfile.write(line + "\n")
                            self.logfile.flush()
                
                self.output_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Error processing output: {e}", file=sys.stderr)
    
    def add_output(self, line, is_error=False):
        """
        Добавляет строку вывода в очередь
        """
        self.output_queue.put((line, is_error))
    
    def stop(self):
        """
        Останавливает обработку вывода
        """
        self.running = False
        self.output_queue.put(None)  # Сигнал завершения
        self.output_thread.join()
        if self.logfile:
            self.logfile.close()

def make_non_blocking(fd):
    """
    Делает файловый дескриптор неблокирующим
    """
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

def read_available(fd):
    """
    Читает доступные данные из файлового дескриптора
    """
    try:
        return fd.read()
    except (IOError, OSError):
        return None

def run_syscall_monitor(args):
    """
    Основная функция для запуска мониторинга системных вызовов
    """
    # Проверяем доступность указанных системных вызовов
    if not args.syscalls:
        print("No syscalls specified. Available syscalls:")
        for syscall in AVAILABLE_MONITORS.keys():
            print(f"  - {syscall}")
        return 1

    # Подготавливаем команды для запуска мониторов
    commands = []
    for syscall in args.syscalls:
        if syscall not in AVAILABLE_MONITORS:
            print(f"Warning: Unknown syscall '{syscall}'. Skipping.")
            continue

        # Получаем имя монитора
        monitor_name = AVAILABLE_MONITORS[syscall]
        
        # Формируем команду
        cmd = ["python3", f"{monitor_name}.py"]
        
        # Добавляем общие параметры (не передаем -T и -U, т.к. они и так по умолчанию включены)
        if args.failed:
            cmd.append("-x")
        if args.pid:
            cmd.extend(["-p", args.pid])
        if args.tid:
            cmd.extend(["-t", args.tid])
        if args.uid:
            cmd.extend(["-u", args.uid])
        if args.name:
            cmd.extend(["-n", args.name])
        if args.extended_fields:
            cmd.append("-e")
        if args.buffer_pages:
            cmd.extend(["-b", str(args.buffer_pages)])
        
        # Добавляем длительность, если указана
        if args.duration:
            cmd.extend(["-d", args.duration])
        
        commands.append((syscall, cmd))

    # Открываем файл для записи, если указан
    logfile = None
    if args.logfile:
        try:
            logfile_path = args.logfile
            if not logfile_path.endswith('.log'):
                logfile_path += '.log'
            
            # Открываем файл в режиме добавления (append), а не перезаписи
            logfile = open(logfile_path, 'a')
            
            # Записываем заголовок с информацией о запуске
            current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            logfile.write(f"\n# ===== syscall_monitor started at {current_time} =====\n")
            logfile.write(f"# Monitoring syscalls: {', '.join(args.syscalls)}\n")
            logfile.write(f"# Command line: {' '.join(sys.argv)}\n\n")
            logfile.flush()
        except Exception as e:
            print(f"Error opening log file: {e}")
            return 1

    # Создаем объект для сбора вывода
    output_collector = OutputCollector(logfile)
    
    # Сообщаем о начале мониторинга
    print(f"Starting monitoring for syscalls: {', '.join(syscall for syscall, _ in commands)}")
    if args.duration:
        print(f"Monitoring will run for {args.duration} seconds")
    if args.logfile:
        print(f"Logging to: {args.logfile} (append mode)")
    print("Press Ctrl+C to stop monitoring")
    
    # Для каждой команды запускаем процесс
    processes = []
    for syscall, cmd in commands:
        try:
            print(f"Starting {syscall} monitor: {' '.join(cmd)}")
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Делаем stdout и stderr неблокирующими
            make_non_blocking(process.stdout)
            make_non_blocking(process.stderr)
            
            processes.append((syscall, process))
        except Exception as e:
            print(f"Error starting {syscall} monitor: {e}")
    
    try:
        # Задаем время окончания, если указана длительность
        end_time = None
        if args.duration:
            duration_seconds = int(args.duration)
            end_time = time.time() + duration_seconds
        
        # Основной цикл сбора данных
        while processes:
            # Проверяем, истекло ли время
            if end_time and time.time() > end_time:
                print("Duration time expired, stopping monitoring")
                break
            
            # Используем select для неблокирующего чтения из stdout и stderr всех процессов
            read_fds = []
            fd_to_process = {}
            for syscall, process in processes:
                if process.stdout:
                    read_fds.append(process.stdout)
                    fd_to_process[process.stdout] = (syscall, process, False)  # False = stdout
                if process.stderr:
                    read_fds.append(process.stderr)
                    fd_to_process[process.stderr] = (syscall, process, True)   # True = stderr
            
            if not read_fds:
                break
            
            # Ждем доступных данных с timeout
            readable, _, _ = select.select(read_fds, [], [], 0.1)
            for fd in readable:
                syscall, process, is_stderr = fd_to_process[fd]
                data = read_available(fd)
                if data:
                    lines = data.strip().split('\n')
                    for line in lines:
                        if line.strip():
                            output_collector.add_output(line, is_stderr)
            
            # Проверяем, не завершились ли процессы
            for i, (syscall, process) in enumerate(processes[:]):
                if process.poll() is not None:
                    # Читаем оставшиеся данные
                    stdout_data = read_available(process.stdout)
                    if stdout_data:
                        for line in stdout_data.strip().split('\n'):
                            if line.strip():
                                output_collector.add_output(line, False)
                    
                    stderr_data = read_available(process.stderr)
                    if stderr_data:
                        for line in stderr_data.strip().split('\n'):
                            if line.strip():
                                output_collector.add_output(line, True)
                    
                    if process.returncode != 0:
                        output_collector.add_output(
                            f"{syscall} monitor exited with code {process.returncode}", True
                        )
                    
                    processes.pop(i)
                    break
        
    except KeyboardInterrupt:
        print("\nReceived keyboard interrupt, stopping monitoring")
    finally:
        # Завершаем все процессы
        for syscall, process in processes:
            if process.poll() is None:
                print(f"Terminating {syscall} monitor")
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    print(f"Killing {syscall} monitor")
                    process.kill()
        
        # Останавливаем сборщик вывода
        output_collector.stop()
        
        # Выводим итоговую информацию
        if args.logfile:
            print(f"Log saved to {args.logfile}")
    
    return 0

def main():
    parser = argparse.ArgumentParser(
        description="Universal system call monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-x", "--failed", action="store_true",
        help="only show failed syscalls")
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
        help="size of the perf ring buffer")
    parser.add_argument("-s", "--syscalls", nargs='+', required=True,
        help="syscalls to monitor (available: " + ", ".join(AVAILABLE_MONITORS.keys()) + ")")
    parser.add_argument("--logfile", 
        help="log output to this file")
    
    args = parser.parse_args()
    sys.exit(run_syscall_monitor(args))

if __name__ == "__main__":
    main() 