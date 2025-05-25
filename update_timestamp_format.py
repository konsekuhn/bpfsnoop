#!/usr/bin/env python3

import os
import re
import sys
import time

def fix_file(filename):
    print(f"Fixing {filename}...")
    with open(filename, 'r') as f:
        content = f.read()
    
    # Add boot_time property
    setup_perf_buffer_pattern = r"(def setup_perf_buffer\(self\):[^\n]*\n(?:[ \t]+[^\n]*\n)+)[ \t]+# header"
    boot_time_addition = r"\1        # Get system boot time for timestamp calculation\n        self.boot_time = self.get_boot_time()\n\n        # header"
    content = re.sub(setup_perf_buffer_pattern, boot_time_addition, content)
    
    # Fix timestamp calculation
    timestamp_pattern = r"# Convert timestamp to datetime format\n[ \t]+ts_seconds = event\.ts / 1000000\n[ \t]+dt = datetime\.fromtimestamp\(ts_seconds\)"
    timestamp_replacement = "# Convert timestamp to datetime format\n                ts_seconds = event.ts / 1000000  # Convert microseconds to seconds\n                real_time = self.boot_time + ts_seconds\n                dt = datetime.fromtimestamp(real_time)"
    content = re.sub(timestamp_pattern, timestamp_replacement, content)
    
    # Add get_boot_time method if not present
    if "def get_boot_time(self)" not in content:
        run_method_pattern = r"([ \t]+def run\(self\):)"
        boot_time_method = '''    def get_boot_time(self):
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

\\1'''
        content = re.sub(run_method_pattern, boot_time_method, content)
    
    with open(filename, 'w') as f:
        f.write(content)
    
    print(f"Fixed {filename}")

def main():
    files_to_fix = [
        "connectsnoop.py",
        "readsnoop.py",
        "writesnoop.py",
        "recvfromsnoop.py",
        "sendtosnoop.py"
    ]
    
    for filename in files_to_fix:
        if os.path.exists(filename):
            fix_file(filename)
        else:
            print(f"File {filename} not found")

if __name__ == "__main__":
    main() 