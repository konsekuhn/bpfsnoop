#!/usr/bin/env python3
import os
import socket
import time
import subprocess

def test_execve():
    print("Testing execve...")
    subprocess.run(["ls", "-l"])

def test_connect():
    print("Testing connect...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(("8.8.8.8", 53))
    except:
        pass
    finally:
        sock.close()

def test_accept():
    print("Testing accept...")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    server.settimeout(1)
    try:
        server.accept()
    except:
        pass
    finally:
        server.close()

def test_sendto():
    print("Testing sendto...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(b"test", ("8.8.8.8", 53))
    except:
        pass
    finally:
        sock.close()

def test_recvfrom():
    print("Testing recvfrom...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(1)
    try:
        sock.recvfrom(1024)
    except:
        pass
    finally:
        sock.close()

def main():
    while True:
        test_execve()
        time.sleep(2)
        test_connect()
        time.sleep(2)
        test_accept()
        time.sleep(2)
        test_sendto()
        time.sleep(2)
        test_recvfrom()
        time.sleep(2)

if __name__ == "__main__":
    main() 