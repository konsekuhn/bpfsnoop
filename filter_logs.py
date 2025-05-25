#!/usr/bin/env python3
# filter_logs.py - Filter syscall monitor logs by syscall type and other criteria
#
# USAGE: filter_logs.py [-h] --input INPUT [--syscall SYSCALL] [--pid PID] [--uid UID]
#                       [--timestamp TIMESTAMP] [--output OUTPUT]
#
# Example: python3 filter_logs.py --input syscall_log.txt --syscall open --output filtered_logs.txt

import argparse
import re
import sys
from datetime import datetime

def parse_args():
    parser = argparse.ArgumentParser(description='Filter syscall monitor logs by various criteria')
    parser.add_argument('--input', '-i', required=True, help='Input log file')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--syscall', '-s', help='Filter by syscall type (e.g., open, read, write)')
    parser.add_argument('--pid', '-p', help='Filter by PID')
    parser.add_argument('--uid', '-u', help='Filter by UID')
    parser.add_argument('--comm', '-c', help='Filter by command name')
    parser.add_argument('--contains', help='Filter lines containing this string')
    parser.add_argument('--after', help='Show entries after this timestamp (format: YYYY-MM-DD HH:MM:SS)')
    parser.add_argument('--before', help='Show entries before this timestamp (format: YYYY-MM-DD HH:MM:SS)')
    parser.add_argument('--failed', '-f', action='store_true', help='Show only failed syscalls (ERR != 0)')
    parser.add_argument('--success', action='store_true', help='Show only successful syscalls (ERR == 0)')
    parser.add_argument('--format', choices=['plain', 'json', 'csv'], default='plain', 
                      help='Output format (default: plain)')
    parser.add_argument('--limit', type=int, help='Limit number of results')
    return parser.parse_args()

def parse_timestamp(timestamp_str):
    """Parse timestamp string to datetime object"""
    if not timestamp_str:
        return None
    try:
        return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S.%f')
    except ValueError:
        try:
            return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            print(f"Error: Invalid timestamp format: {timestamp_str}")
            print("Expected format: YYYY-MM-DD HH:MM:SS[.mmm]")
            sys.exit(1)

def extract_timestamp(line):
    """Extract timestamp from log line"""
    timestamp_match = re.match(r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\]', line)
    if timestamp_match:
        return parse_timestamp(timestamp_match.group(1))
    return None

def extract_syscall(line):
    """Extract syscall from log line"""
    syscall_match = re.search(r'SYSCALL=(\w+)', line)
    if syscall_match:
        return syscall_match.group(1)
    return None

def extract_pid(line):
    """Extract PID from log line"""
    pid_match = re.search(r'PID=(\d+)', line)
    if pid_match:
        return pid_match.group(1)
    return None

def extract_uid(line):
    """Extract UID from log line"""
    uid_match = re.search(r'UID=(\d+)', line)
    if uid_match:
        return uid_match.group(1)
    return None

def extract_comm(line):
    """Extract command name from log line"""
    comm_match = re.search(r'COMM=(\S+)', line)
    if comm_match:
        return comm_match.group(1)
    return None

def extract_error(line):
    """Extract error code from log line"""
    err_match = re.search(r'ERR=(-?\d+)', line)
    if err_match:
        return int(err_match.group(1))
    return None

def filter_logs(args):
    """Filter log files based on criteria"""
    try:
        with open(args.input, 'r') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading input file: {str(e)}")
        sys.exit(1)
    
    # Parse timestamp filters
    after_timestamp = parse_timestamp(args.after)
    before_timestamp = parse_timestamp(args.before)
    
    # Initialize output
    output_lines = []
    count = 0
    
    # Process each line
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        # Skip session markers unless explicitly asked for this syscall
        if "=== STARTING NEW MONITORING SESSION ===" in line or "=== ENDING MONITORING SESSION ===" in line:
            if not args.contains or args.contains in line:
                output_lines.append(line)
            continue
        
        # Extract fields for filtering
        timestamp = extract_timestamp(line)
        syscall = extract_syscall(line)
        pid = extract_pid(line)
        uid = extract_uid(line)
        comm = extract_comm(line)
        err = extract_error(line)
        
        # Apply filters
        if args.syscall and (not syscall or args.syscall.lower() != syscall.lower()):
            continue
            
        if args.pid and (not pid or args.pid != pid):
            continue
            
        if args.uid and (not uid or args.uid != uid):
            continue
            
        if args.comm and (not comm or args.comm not in comm):
            continue
            
        if args.contains and args.contains not in line:
            continue
            
        if after_timestamp and (not timestamp or timestamp < after_timestamp):
            continue
            
        if before_timestamp and (not timestamp or timestamp > before_timestamp):
            continue
            
        if args.failed and (err is None or err == 0):
            continue
            
        if args.success and (err is None or err != 0):
            continue
        
        # Add line to output
        output_lines.append(line)
        count += 1
        
        # Check limit
        if args.limit and count >= args.limit:
            break
    
    # Format output
    if args.format == 'json':
        # Implement JSON formatting if needed
        formatted_output = format_as_json(output_lines)
    elif args.format == 'csv':
        # Implement CSV formatting if needed
        formatted_output = format_as_csv(output_lines)
    else:
        # Plain text format
        formatted_output = '\n'.join(output_lines)
    
    # Write output
    if args.output:
        try:
            with open(args.output, 'w') as f:
                f.write(formatted_output)
            print(f"Filtered logs written to {args.output} ({len(output_lines)} lines)")
        except Exception as e:
            print(f"Error writing output file: {str(e)}")
            sys.exit(1)
    else:
        print(formatted_output)

def format_as_json(lines):
    """Format lines as JSON"""
    # Simple implementation - can be enhanced for better JSON structure
    import json
    return json.dumps(lines, indent=2)

def format_as_csv(lines):
    """Format lines as CSV"""
    # Simple implementation - can be enhanced for better CSV structure
    import csv
    import io
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    for line in lines:
        # Very simple CSV formatting - just put each line as a row
        writer.writerow([line])
    
    return output.getvalue()

if __name__ == "__main__":
    args = parse_args()
    filter_logs(args) 