#!/usr/bin/env python3
# 
# logfilter.py  Инструмент для фильтрации логов syscall_monitor
#
# USAGE: logfilter.py [-h] [--syscall SYSCALL] [--pid PID] [--uid UID]
#                     [--comm COMM] [--status {success,error,all}]
#                     [--date DATE] [--time TIME] [--path PATH]
#                     [--logfile LOGFILE] [--output OUTPUT]
#

import argparse
import re
import sys
import datetime
import os

# Словарь, ассоциирующий типы системных вызовов с их идентификаторами в логах
SYSCALL_IDENTIFIERS = {
    'open': ('PATH', 'FD', 'ERR'),       # Для open: столбцы PATH, FD, ERR
    'connect': ('IP:PORT', 'ERR'),       # Для connect: столбцы IP:PORT, ERR
    'accept': ('IP:PORT', 'ERR'),        # Для accept: столбцы IP:PORT, ERR
    'execve': ('ARGS', 'ERR'),           # Для execve: столбцы ARGS, ERR
    'read': ('FD', 'BYTES', 'ERR'),      # Для read: столбцы FD, BYTES, ERR
    'write': ('FD', 'BYTES', 'ERR'),     # Для write: столбцы FD, BYTES, ERR
    'recvfrom': ('FD', 'IP:PORT', 'BYTES', 'ERR'),  # Для recvfrom: столбцы FD, IP:PORT, BYTES, ERR
    'sendto': ('FD', 'IP:PORT', 'BYTES', 'ERR')     # Для sendto: столбцы FD, IP:PORT, BYTES, ERR
}

def detect_syscall_type(line):
    """
    Определяет тип системного вызова по строке лога
    Возвращает тип вызова или None, если не удалось определить
    """
    # Перебираем все типы системных вызовов и их идентификаторы
    for syscall, identifiers in SYSCALL_IDENTIFIERS.items():
        # Проверяем наличие всех идентификаторов в строке заголовка
        if all(ident in line for ident in identifiers):
            return syscall
    return None

def parse_log_session(log_lines):
    """
    Разбирает сессию логов на заголовок и данные
    Возвращает кортеж (заголовок, записи)
    """
    header = []
    entries = []
    current_syscall = None
    header_seen = False
    table_header = None
    
    # Проходим по строкам лога
    for line in log_lines:
        line = line.strip()
        if not line:
            continue
            
        # Проверяем, является ли строка заголовком сессии
        if line.startswith('# ====='):
            header = [line]
            header_seen = True
            current_syscall = None
            table_header = None
        # Находим тип системного вызова из строки "# Monitoring syscalls: X"
        elif header_seen and line.startswith('# Monitoring syscalls:'):
            header.append(line)
            # Извлекаем тип системного вызова из строки
            syscalls_part = line.split(':', 1)[1].strip()
            # Если указано несколько системных вызовов, берем первый
            current_syscall = syscalls_part.split()[0].strip()
        # Добавляем строку в заголовок, если она начинается с #
        elif line.startswith('#'):
            header.append(line)
        # Проверяем, является ли строка заголовком таблицы
        elif 'TIMESTAMP' in line and 'UID' in line and 'PID' in line:
            header.append(line)
            table_header = line
        # Иначе считаем строку записью данных
        elif line and current_syscall and table_header:
            # Проверяем, что строка содержит достаточно полей
            fields = line.split()
            if len(fields) >= 5:  # timestamp, uid, pid, comm, ...
                # Добавляем запись вместе с типом системного вызова
                entries.append((current_syscall, line))
    
    return (header, entries)

def filter_entries(entries, args):
    """
    Фильтрует записи по заданным критериям
    """
    filtered = []
    
    for syscall_type, entry in entries:
        # Фильтр по типу системного вызова
        if args.syscall and args.syscall.lower() != syscall_type.lower():
            continue
            
        # Разбиваем строку на поля, учитывая, что дата и время могут содержать пробелы
        fields = entry.split()
        if len(fields) < 5:  # Минимум должны быть timestamp, uid, pid, comm
            continue
            
        # Выделяем поля с датой и временем (могут быть разделены пробелом)
        date_time = " ".join(fields[:2])
        # Остальные поля
        uid = fields[2]
        pid = fields[3]
        comm = fields[4]
        
        # Фильтр по дате (может быть частичное совпадение)
        if args.date and args.date not in date_time:
            continue
            
        # Фильтр по времени (может быть частичное совпадение)
        if args.time and args.time not in date_time:
            continue
            
        # Фильтр по UID
        if args.uid and args.uid != uid:
            continue
            
        # Фильтр по PID
        if args.pid and args.pid != pid:
            continue
            
        # Фильтр по имени процесса (может быть частичное совпадение)
        if args.comm and args.comm.lower() not in comm.lower():
            continue
            
        # Фильтр по пути (для тех syscall, где применимо)
        if args.path:
            path_match = False
            # Объединяем все оставшиеся поля для поиска пути
            rest_of_entry = " ".join(fields[5:])
            
            # Если путь содержится в оставшейся части записи
            if args.path.lower() in rest_of_entry.lower():
                path_match = True
                
            if not path_match:
                continue
                
        # Фильтр по статусу (успех/ошибка)
        if args.status != 'all':
            # Определяем успешность операции по коду ошибки
            # В разных syscall поле ERR может быть в разных позициях
            error_code = None
            
            # Находим поле ERR
            for i, field in enumerate(fields[5:], 5):
                if field.isdigit() or (field.startswith('-') and field[1:].isdigit()):
                    # Потенциальный код ошибки
                    if int(field) < 0:  # Отрицательное значение обычно означает ошибку
                        error_code = int(field)
                        break
            
            if args.status == 'success' and error_code is not None and error_code < 0:
                continue
            if args.status == 'error' and (error_code is None or error_code >= 0):
                continue
                
        # Если прошли все фильтры, добавляем запись
        filtered.append((syscall_type, entry))
    
    return filtered

def format_output(header, filtered_entries, args):
    """
    Форматирует вывод на основе отфильтрованных записей
    """
    output = []
    
    # Добавляем информацию о фильтрации
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    output.append(f"# Filtered log - {current_time}")
    
    # Добавляем информацию о примененных фильтрах
    filters = []
    if args.syscall: 
        filters.append(f"syscall={args.syscall}")
    if args.pid: 
        filters.append(f"pid={args.pid}")
    if args.uid: 
        filters.append(f"uid={args.uid}")
    if args.comm: 
        filters.append(f"comm={args.comm}")
    if args.status and args.status != 'all': 
        filters.append(f"status={args.status}")
    if args.date: 
        filters.append(f"date={args.date}")
    if args.time: 
        filters.append(f"time={args.time}")
    if args.path: 
        filters.append(f"path={args.path}")
    
    if filters:
        output.append(f"# Filters applied: {', '.join(filters)}")
    else:
        output.append("# No filters applied")
    
    output.append("")
    
    # Добавляем заголовок таблицы, если есть записи
    if filtered_entries:
        # Ищем строку заголовка таблицы
        table_header = None
        for line in header:
            if 'TIMESTAMP' in line and 'UID' in line and 'PID' in line:
                table_header = line
                break
        
        if table_header:
            output.append(table_header)
    
    # Добавляем отфильтрованные записи
    for _, entry in filtered_entries:
        output.append(entry)
    
    # Добавляем статистику
    output.append("")
    output.append(f"# Total entries: {len(filtered_entries)}")
    
    # Считаем статистику по типам системных вызовов
    syscall_counts = {}
    for syscall_type, _ in filtered_entries:
        syscall_counts[syscall_type] = syscall_counts.get(syscall_type, 0) + 1
    
    # Выводим статистику
    if syscall_counts:
        output.append("# Syscalls breakdown:")
        for syscall, count in sorted(syscall_counts.items()):
            output.append(f"#   {syscall}: {count}")
    
    return output

def main():
    parser = argparse.ArgumentParser(
        description="Фильтр логов системных вызовов",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Параметры фильтрации
    parser.add_argument("--syscall", help="тип системного вызова для фильтрации")
    parser.add_argument("--pid", help="фильтр по PID")
    parser.add_argument("--uid", help="фильтр по UID")
    parser.add_argument("--comm", help="фильтр по имени процесса (COMM)")
    parser.add_argument("--status", choices=['success', 'error', 'all'], default='all',
                      help="фильтр по статусу (успех/ошибка)")
    parser.add_argument("--date", help="фильтр по дате (YYYY-MM-DD)")
    parser.add_argument("--time", help="фильтр по времени (HH:MM:SS)")
    parser.add_argument("--path", help="фильтр по пути/URL/IP")
    
    # Параметры ввода/вывода
    parser.add_argument("--logfile", required=True, help="путь к лог-файлу")
    parser.add_argument("--output", help="путь для сохранения отфильтрованного лога (по умолчанию stdout)")
    
    args = parser.parse_args()
    
    # Проверяем существование лог-файла
    if not os.path.exists(args.logfile):
        print(f"Ошибка: файл {args.logfile} не существует", file=sys.stderr)
        return 1
    
    # Читаем лог-файл
    try:
        with open(args.logfile, 'r') as f:
            log_lines = f.readlines()
    except Exception as e:
        print(f"Ошибка при чтении файла {args.logfile}: {e}", file=sys.stderr)
        return 1
    
    # Разбираем лог на сессии и записи
    header, entries = parse_log_session(log_lines)
    
    # Фильтруем записи
    filtered_entries = filter_entries(entries, args)
    
    # Форматируем вывод
    output_lines = format_output(header, filtered_entries, args)
    
    # Выводим результат
    if args.output:
        try:
            with open(args.output, 'w') as f:
                for line in output_lines:
                    f.write(line + "\n")
            print(f"Отфильтрованный лог сохранен в {args.output}")
        except Exception as e:
            print(f"Ошибка при записи в файл {args.output}: {e}", file=sys.stderr)
            return 1
    else:
        for line in output_lines:
            print(line)
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 