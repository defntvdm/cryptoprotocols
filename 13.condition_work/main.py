#!/usr/bin/env python3

import asyncio
import os
from socket import socket, AF_INET, SOCK_DGRAM


PERSENTAGE = 0
TRASH = []
NEED_PRINT = True


def add_file_reader(fd: int):
    def _read_ready():
        global PERSENTAGE
        try:
            data = os.read(fd, 2048).decode('utf-8')
            if not data:
                return
            lines = data.split('\n')
            total, avail = None, None
            for l in lines: # type: str
                if l.startswith('MemTotal'):
                    total = int(l.split()[1].strip())
                if l.startswith('MemAvailable'):
                    avail = int(l.split()[1].strip())
            if avail is not None and total is not None:
                PERSENTAGE = 100 - avail * 100 / total
            os.lseek(fd, 0, os.SEEK_SET)
        except Exception as exc:
            print(exc)
    asyncio.get_event_loop().add_reader(fd, _read_ready)


def add_socket_reader(sock):
    def _read_ready():
        global NEED_PRINT
        try:
            data, addr = sock.recvfrom(65536)
            if data and PERSENTAGE < 70:
                NEED_PRINT = True
                TRASH.append(data)
            else:
                if NEED_PRINT:
                    print('АХТУНГ!!! ПАМЯТЬ')
                NEED_PRINT = False
                sock.sendto('Воу-воу, памяти накиньте!!!\n'.encode('utf-8'), addr)
        except Exception as exc:
            print(exc)
    asyncio.get_event_loop().add_reader(sock.fileno(), _read_ready)


async def printer():
    while True:
        print('Percentage:', '{:.2f}'.format(PERSENTAGE))
        await asyncio.sleep(5)


def main():
    if os.name != 'posix':
        print('Posix only')
        exit(1)
    loop = asyncio.get_event_loop()
    file_fd = None
    sock = None
    try:
        file_fd = os.open('/proc/meminfo', os.O_RDONLY | os.O_NONBLOCK)
        add_file_reader(file_fd)

        sock = socket(AF_INET, SOCK_DGRAM)
        sock.bind(('', 31337))
        add_socket_reader(sock)

        asyncio.ensure_future(printer())

        loop.run_forever()
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if sock is not None:
            sock.close()
        loop.close()


if __name__ == '__main__':
    main()
