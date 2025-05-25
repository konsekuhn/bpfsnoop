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

# Словарь доступных мониторов системных вызовов
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
            # Используем subprocess.Popen для запуска команды в отдельном процессе
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1  # Построчная буферизация
            )
            
            # Делаем вывод неблокирующим
            make_non_blocking(process.stdout)
            make_non_blocking(process.stderr)
            
            processes.append((syscall, process))
        except Exception as e:
            output_collector.add_output(f"Failed to start {syscall} monitor: {e}", is_error=True)
    
    # Если нет запущенных процессов, завершаем работу
    if not processes:
        output_collector.add_output("No monitors were started", is_error=True)
        output_collector.stop()
        return 1
    
    # Создаем словарь для отслеживания начала вывода от каждого процесса
    process_started_output = {syscall: False for syscall, _ in processes}
    
    # Основной цикл обработки вывода процессов
    try:
        # Если указана длительность, вычисляем время окончания
        end_time = None
        if args.duration:
            end_time = time.time() + int(args.duration)
        
        # Ждем, пока все процессы завершатся или наступит время окончания
        while processes:
            # Проверяем, не истекло ли время выполнения
            if end_time and time.time() >= end_time:
                break
                
            # Проверяем вывод от каждого процесса
            for i, (syscall, process) in enumerate(processes[:]):
                # Проверяем, не завершился ли процесс
                if process.poll() is not None:
                    # Процесс завершился, читаем оставшийся вывод
                    stdout = read_available(process.stdout)
                    if stdout:
                        for line in stdout.splitlines():
                            output_collector.add_output(f"[{syscall}] {line}")
                    
                    stderr = read_available(process.stderr)
                    if stderr:
                        for line in stderr.splitlines():
                            output_collector.add_output(f"[{syscall}] {line}", is_error=True)
                    
                    # Если процесс завершился с ошибкой, выводим сообщение
                    if process.returncode != 0:
                        output_collector.add_output(
                            f"{syscall} monitor exited with code {process.returncode}", 
                            is_error=True
                        )
                    
                    # Удаляем процесс из списка
                    processes.remove((syscall, process))
                    continue
                
                # Читаем доступный вывод из stdout
                stdout = read_available(process.stdout)
                if stdout:
                    process_started_output[syscall] = True
                    for line in stdout.splitlines():
                        output_collector.add_output(f"[{syscall}] {line}")
                
                # Читаем доступный вывод из stderr
                stderr = read_available(process.stderr)
                if stderr:
                    process_started_output[syscall] = True
                    for line in stderr.splitlines():
                        output_collector.add_output(f"[{syscall}] {line}", is_error=True)
            
            # Небольшая пауза, чтобы не нагружать CPU
            time.sleep(0.1)
            
        # Корректно завершаем все процессы
        for syscall, process in processes:
            try:
                process.terminate()
                # Даем процессу немного времени для корректного завершения
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                # Если процесс не завершился, принудительно убиваем его
                process.kill()
                output_collector.add_output(f"Had to kill {syscall} monitor process", is_error=True)
    
    except KeyboardInterrupt:
        # Пользователь нажал Ctrl+C, завершаем все процессы
        output_collector.add_output("Interrupted by user. Stopping all monitors...")
        
        for syscall, process in processes:
            try:
                process.terminate()
                # Даем процессу немного времени для корректного завершения
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                # Если процесс не завершился, принудительно убиваем его
                process.kill()
                output_collector.add_output(f"Had to kill {syscall} monitor process", is_error=True)
    
    finally:
        # Останавливаем сборщик вывода
        output_collector.stop()
    
    return 0

def main():
    parser = argparse.ArgumentParser(
        description="Universal system call monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-x", "--failed", action="store_true",
        help="only show failed syscalls")
    parser.add_argument("-p", "--pid", type=str,
        help="trace this PID only")
    parser.add_argument("-t", "--tid", type=str,
        help="trace this TID only")
    parser.add_argument("-u", "--uid", type=str,
        help="trace this UID only")
    parser.add_argument("-d", "--duration", type=str,
        help="total duration of trace in seconds")
    parser.add_argument("-n", "--name", type=str,
        help="only print process names containing this name")
    parser.add_argument("-e", "--extended_fields", action="store_true",
        help="show extended fields (where available)")
    parser.add_argument("-b", "--buffer-pages", type=str,
        help="number of BPF ring buffer pages")
    parser.add_argument("-s", "--syscalls", nargs="+", type=str,
        help="list of syscalls to monitor")
    parser.add_argument("--logfile", type=str,
        help="log output to this file")
    
    args = parser.parse_args()
    return run_syscall_monitor(args)

if __name__ == "__main__":
    sys.exit(main()) 