# cli/transport/winrm_transport.py
import os
import uuid
import json
from pathlib import Path
from colorama import Fore, Style

from .winrmexec import NTCredential, SPNEGOTransport, Runspace
from .evil_winrmexec import EvilShell

class PSResponse:
    def __init__(self, stdout="", stderr="", status_code=0):
        self.std_out = stdout.encode('utf-8')
        self.std_err = stderr.encode('utf-8')
        self.status_code = status_code

class WinRMTransport:
    def __init__(self, host, user, password='', domain='', http_listen_address='', http_port=0, http_server_auto_stop=False, lmhash='', nthash=''):
        self.target_ip = host
        self.username = user
        self.password = password
        self.domain = domain
        self.lmhash = lmhash
        self.nthash = nthash

        # Неиспользуемые параметры – для совместимости
        self.http_listen_address = http_listen_address
        self.http_port = http_port
        self.http_server_auto_stop = http_server_auto_stop

        self.is_admin = False

        # Создаём URL для WinRM
        url = f"http://{self.target_ip}:5985/wsman"

        # Подготовка учётных данных
        if self.nthash:
            creds = NTCredential(self.domain, self.username, password="", nt_hash=self.nthash)
        else:
            creds = NTCredential(self.domain, self.username, password=self.password, nt_hash="")

        self.transport = SPNEGOTransport(url, creds)
        self.runspace = Runspace(self.transport, timeout=10)
        self.runspace.__enter__()

        self.evil = EvilShell(self.runspace)

        # Получение TEMP директории
        try:
            result = self._run_ps("$env:TEMP")
            real_temp = result.std_out.decode('utf-8', errors='replace').strip()
            if real_temp:
                self.remote_base = f"{real_temp}\\collector_{uuid.uuid4().hex[:8]}"
            else:
                self.remote_base = f"C:\\Windows\\Temp\\collector_{uuid.uuid4().hex[:8]}"
        except:
            self.remote_base = f"C:\\Windows\\Temp\\collector_{uuid.uuid4().hex[:8]}"

        print(f"{Fore.GREEN}[+] Connected. Staging dir: {self.remote_base}{Style.RESET_ALL}")

    def _run_ps(self, cmd):
        stdout = []
        stderr = []
        status_code = 0
        try:
            for out in self.runspace.run_command(cmd):
                if "stdout" in out:
                    stdout.append(out["stdout"])
                elif "error" in out:
                    stderr.append(out["error"])
                    status_code = 1
        except Exception as e:
            stderr.append(str(e))
            status_code = 1
        return PSResponse("\n".join(stdout), "\n".join(stderr), status_code)

    def _ensure_dir(self, path):
        cmd = f"if (-not (Test-Path -Path '{path}')) {{ New-Item -ItemType Directory -Force -Path '{path}' | Out-Null }}"
        r = self._run_ps(cmd)
        return r.status_code == 0

    def _check_admin_rights(self):
        cmd = "([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
        r = self._run_ps(cmd)
        output = r.std_out.decode('utf-8', errors='replace').strip()
        print(f"    Admin check result: '{output}'")
        return output.lower() == "true"

    def _upload_file(self, local_path, remote_path):
        """Загружает один файл через EvilShell.upload."""
        print(f"    Uploading {os.path.basename(local_path)} via WinRM...")
        # Формируем аргументы: путь локальный и удалённый в кавычках
        args = f'"{local_path}" "{remote_path}"'
        self.evil.upload(args)
        print(f"    {Fore.GREEN}[✓]{Style.RESET_ALL} Uploaded: {os.path.basename(local_path)}")
        return True

    def _upload_dir(self, local_dir, remote_dir):
        """Рекурсивно загружает всю директорию."""
        local_dir = os.path.abspath(local_dir)
        for root, dirs, files in os.walk(local_dir):
            rel = os.path.relpath(root, local_dir).replace(os.sep, '\\')
            curr_remote = f"{remote_dir}\\{rel}" if rel != '.' else remote_dir
            self._ensure_dir(curr_remote)
            for fname in files:
                local_file = os.path.join(root, fname)
                remote_file = f"{curr_remote}\\{fname}"
                self._upload_file(local_file, remote_file)

    def deploy(self, local_project_root):
        # Создаём структуру папок на удалённой машине
        self._ensure_dir(self.remote_base)
        self._ensure_dir(f"{self.remote_base}\\runner")
        self._ensure_dir(f"{self.remote_base}\\modules")
        self._ensure_dir(f"{self.remote_base}\\output")

        # Копируем runner.ps1
        runner_src = os.path.join(local_project_root, "runner", "runner.ps1")
        if os.path.exists(runner_src):
            self._upload_file(runner_src, f"{self.remote_base}\\runner\\runner.ps1")
        else:
            print(f"{Fore.RED}[!] runner.ps1 not found at {runner_src}{Style.RESET_ALL}")

        # Копируем модули
        modules_src = os.path.join(local_project_root, "modules")
        if os.path.exists(modules_src):
            self._upload_dir(modules_src, f"{self.remote_base}\\modules")

        self.is_admin = self._check_admin_rights()
        self._save_privilege_info()
        print(f"{Fore.GREEN}[+] Deployment complete.{Style.RESET_ALL}")

    def _save_privilege_info(self):
        privilege_data = {
            "is_admin": self.is_admin,
            "transport": "WinRM (evil_winrm)",
            "user": self.username
        }
        json_str = json.dumps(privilege_data, indent=2)
        json_escaped = json_str.replace("'", "''")
        ps_cmd = f"$json = '{json_escaped}' | ConvertFrom-Json; $json | ConvertTo-Json -Depth 5 | Out-File '{self.remote_base}\\output\\privilege.json' -Encoding UTF8"
        self._run_ps(ps_cmd)

    def run_module(self, cmd):
        runner_path = f"{self.remote_base}\\runner\\runner.ps1"
        ps_cmd = f'powershell -NoProfile -ExecutionPolicy Bypass -File "{runner_path}" {cmd}'
        print(f"{Fore.CYAN}[*] Executing: {cmd} ...{Style.RESET_ALL}")
        r = self._run_ps(ps_cmd)
        if r.std_out:
            print(r.std_out.decode('utf-8', errors='replace'))
        if r.status_code != 0 and r.std_err:
            print(f"{Fore.RED}[!] STDERR: {r.std_err.decode('utf-8', errors='replace')[:500]}{Style.RESET_ALL}")
        return r.status_code

    def retrieve_archive(self):
        print(f"{Fore.YELLOW}[*] Retrieving archive...{Style.RESET_ALL}")
        find_cmd = f"Get-ChildItem '{self.remote_base}\\output' -Filter '*.zip' | Sort LastWriteTime -Descending | Select -First 1 -Expand FullName"
        r = self._run_ps(find_cmd)
        zip_path = r.std_out.decode('utf-8', errors='replace').strip()
        if not zip_path or "Get-ChildItem" in zip_path:
            print(f"{Fore.RED}[!] No archive found.{Style.RESET_ALL}")
            return False

        local_zip = os.path.join("output", os.path.basename(zip_path))
        os.makedirs("output", exist_ok=True)

        # Скачиваем через evil.download
        args = f'"{zip_path}" "{local_zip}"'
        self.evil.download(args)
        print(f"{Fore.GREEN}[+] Downloaded via WinRM: {local_zip}{Style.RESET_ALL}")
        return True

    def cleanup(self):
        print(f"{Fore.YELLOW}[*] Cleaning up...{Style.RESET_ALL}")
        self._run_ps(f"Remove-Item '{self.remote_base}' -Recurse -Force -ErrorAction SilentlyContinue")
        print(f"{Fore.GREEN}[+] Cleanup complete.{Style.RESET_ALL}")
        try:
            self.runspace.__exit__(None, None, None)
        except:
            pass