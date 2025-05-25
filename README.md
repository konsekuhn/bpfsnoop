Набор инструментов для мониторинга системных вызовов Linux и анализа собранных данных.
Компоненты
syscall_monitor.py: Основной инструмент для мониторинга системных вызовов в реальном времени
filter_logs.py: Инструмент для фильтрации и анализа лог-файлов, созданных syscall_monitor
Различные snoop-инструменты: Индивидуальные мониторы для конкретных системных вызовов (opensnoop.py, readsnoop.py и т.д.)

# Мониторинг системных вызовов open и read с выводом в терминал и лог-файл
python3 syscall_monitor.py -s open read --logfile syscall_logs.txt

# Мониторинг всех доступных системных вызовов
python3 syscall_monitor.py -s open read write connect accept execve recvfrom sendto --logfile all_syscalls.txt

# Мониторинг конкретного процесса по PID
python3 syscall_monitor.py -s open read -p 1234 --logfile proc_1234_syscalls.txt

# Мониторинг конкретного пользователя по UID
python3 syscall_monitor.py -s open write -u 1000 --logfile user_1000_syscalls.txt

# Мониторинг на определенную продолжительность (в секундах)
python3 syscall_monitor.py -s open -d 60 --logfile one_minute_open_calls.txt

### Filtering Log Files

Use the filter_logs.py tool to analyze and filter the log files produced by syscall_monitor:

```bash
# Фильтрация логов для отображения только системных вызовов 'open'
python3 filter_logs.py --input syscall_logs.txt --syscall open

# Фильтрация логов для отображения только системных вызовов от конкретного PID
python3 filter_logs.py --input syscall_logs.txt --pid 1234

# Фильтрация логов для отображения только системных вызовов от конкретного UID
python3 filter_logs.py --input syscall_logs.txt --uid 1000

# Фильтрация логов по временной метке (после определенного времени)
python3 filter_logs.py --input syscall_logs.txt --after "2023-01-01 12:00:00"

# Фильтрация логов по временной метке (до определенного времени)
python3 filter_logs.py --input syscall_logs.txt --before "2023-01-01 13:00:00"

# Комбинирование нескольких фильтров
python3 filter_logs.py --input syscall_logs.txt --syscall open --pid 1234 --output filtered_logs.txt

# Фильтрация логов, содержащих определенный текст
python3 filter_logs.py --input syscall_logs.txt --contains "/etc/passwd"
```

Доступные мониторы системных вызовов
open: Мониторинг операций открытия файлов
read: Мониторинг операций чтения из файлов
write: Мониторинг операций записи в файлы
connect: Мониторинг попыток сетевых подключений
accept: Мониторинг входящих сетевых подключений
execve: Мониторинг запуска программ
recvfrom: Мониторинг приема сетевых данных
sendto: Мониторинг передачи сетевых данных

Формат логов
Лог-файлы используют следующий формат для каждой записи:

```
[TIMESTAMP] SYSCALL=syscall_name data1 data2 ...
additional lines of data...
```

Каждая запись начинается с временной метки и идентификатора системного вызова, за которыми следуют специфические для этого системного вызова данные.

Требования
Ядро Linux 4.9 или новее
Python 3.6 или новее
BCC (BPF Compiler Collection)
