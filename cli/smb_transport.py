# cli/transport/smb_transport.py
import os
from impacket.smbconnection import SMBConnection
from colorama import Fore, Style

class SMBTransport:
    def __init__(self, remote_host, username, password='', domain='', lmhash='', nthash=''):
        self.remote_host = remote_host
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = lmhash
        self.nthash = nthash
        self.conn = None

    def connect(self):
        try:
            self.conn = SMBConnection(self.remote_host, self.remote_host, sess_port=445)
            # Impacket's login supports lmhash/nthash via keyword args
            if self.lmhash or self.nthash:
                self.conn.login(self.username, '', self.domain, lmhash=self.lmhash, nthash=self.nthash)
            else:
                self.conn.login(self.username, self.password, self.domain)
            return True
        except Exception as e:
            print(f"    SMB connection error: {e}")
            return False

    def upload_file(self, local_path, remote_path):
        """
        Загружает файл на удалённую машину.
        remote_path: абсолютный путь Windows, например 'C:\\folder\\file.ext'
        """
        if not self.conn:
            return False
        try:
            # Буква диска — первый символ пути
            drive_letter = remote_path[0]           # 'C'
            share = drive_letter + '$'              # 'C$'
            # Путь внутри шары: убираем "C:\" (первые 3 символа) и заменяем \ на /
            path_in_share = remote_path[3:].replace('\\', '/')
            with open(local_path, 'rb') as f:
                self.conn.putFile(share, path_in_share, f.read)
            return True
        except Exception as e:
            print(f"    SMB upload error: {e}")
            return False

    def download_file(self, remote_path, local_path):
        if not self.conn:
            return False
        try:
            drive_letter = remote_path[0]
            share = drive_letter + '$'
            path_in_share = remote_path[3:].replace('\\', '/')
            with open(local_path, 'wb') as f:
                self.conn.getFile(share, path_in_share, f.write)
            return True
        except Exception as e:
            print(f"    SMB download error: {e}")
            return False

    def create_directory(self, remote_path):
        if not self.conn:
            return False
        try:
            drive_letter = remote_path[0]
            share = drive_letter + '$'
            path_in_share = remote_path[3:].replace('\\', '/')
            self.conn.createDirectory(share, path_in_share)
            return True
        except Exception:
            # Папка может уже существовать – не считаем ошибкой
            return True

    def disconnect(self):
        if self.conn:
            self.conn.close()
            self.conn = None