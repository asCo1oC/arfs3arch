#!/usr/bin/env python3
# tools/http_server.py - фоновый HTTP-сервер для раздачи больших файлов

import os
import sys
import argparse
import http.server
import socketserver
import json
import time
from pathlib import Path

# Путь к директории с файлами для раздачи (tools)
TOOLS_DIR = Path(__file__).parent.absolute()

class QuietHTTPHandler(http.server.SimpleHTTPRequestHandler):
    """Хендлер с минимальным логированием (выводит только ошибки)"""
    def log_message(self, format, *args):
        # Можно раскомментировать для отладки:
        # print(f"[HTTP] {format % args}")
        pass

    def log_error(self, format, *args):
        print(f"[HTTP ERROR] {format % args}", file=sys.stderr)

def main():
    parser = argparse.ArgumentParser(description='HTTP server for collector tools')
    parser.add_argument('--host', default='0.0.0.0', help='Bind address')
    parser.add_argument('--port', type=int, default=8888, help='Bind port')
    parser.add_argument('--pidfile', help='File to write PID')
    args = parser.parse_args()

    # Переключаемся в директорию tools
    os.chdir(TOOLS_DIR)

    # Создаём сервер с переиспользованием порта (SO_REUSEADDR)
    class ReuseTCPServer(socketserver.TCPServer):
        allow_reuse_address = True

    with ReuseTCPServer((args.host, args.port), QuietHTTPHandler) as httpd:
        print(f"HTTP server running at http://{args.host}:{args.port}")
        print(f"Serving directory: {TOOLS_DIR}")

        if args.pidfile:
            with open(args.pidfile, 'w') as f:
                f.write(str(os.getpid()))

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down...")
        finally:
            if args.pidfile and os.path.exists(args.pidfile):
                os.unlink(args.pidfile)

if __name__ == '__main__':
    main()