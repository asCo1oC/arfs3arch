# cli/transport/winrm_transport.py
import os
import uuid
import base64
import time
import socket
import subprocess
import shutil
import sys
import json
import psutil
from colorama import Fore, Style
from pathlib import Path

# Импортируем winrmexec
from .winrmexec import NTCredential, SPNEGOTransport, Runspace

try:
    from impacket.smbconnection import SMBConnection
    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False
    print(f"{Fore.YELLOW}[!] Impacket not installed. SMB transport will be unavailable. Install: pip install impacket{Style.RESET_ALL}")

LARGE_FILE_THRESHOLD = 500 * 1024   # 500 KB

from .smb_transport import SMBTransport

# Вспомогательный класс для эмуляции Response от pywinrm
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
        self.http_listen_address = http_listen_address
        self.http_port = http_port
        self.http_server_auto_stop = http_server_auto_stop
        self.http_server_process = None
        self.pid_file = None
        self.is_admin = False
        self.smb_available = False
        self.smb_transport = None
        self.lmhash = lmhash
        self.nthash = nthash

        # Создаём URL для WinRM
        url = f"http://{self.target_ip}:5985/wsman"

        # Подготавливаем учётные данные
        if self.nthash:
            # Используем NTLM-хеш
            creds = NTCredential(self.domain, self.username, password="", nt_hash=self.nthash)
        else:
            creds = NTCredential(self.domain, self.username, password=self.password, nt_hash="")

        # Создаём транспорт
        self.transport = SPNEGOTransport(url, creds)

        # Создаём runspace и входим в контекст
        self.runspace = Runspace(self.transport, timeout=10)
        self.runspace.__enter__()   # эквивалент with Runspace(...) as runspace

        # Получаем реальный TEMP
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
        """
        Выполняет PowerShell команду и возвращает PSResponse с stdout, stderr и кодом.
        """
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
                elif "warn" in out:
                    # предупреждения не считаем ошибкой
                    pass
        except Exception as e:
            stderr.append(str(e))
            status_code = 1

        return PSResponse("\n".join(stdout), "\n".join(stderr), status_code)

    def _ensure_dir(self, path):
        cmd = f"if (-not (Test-Path -Path '{path}')) {{ New-Item -ItemType Directory -Force -Path '{path}' | Out-Null }}"
        r = self._run_ps(cmd)
        return r.status_code == 0

    # ---------- Проверка прав и SMB ----------
    def _check_admin_rights(self):
        cmd = "([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
        r = self._run_ps(cmd)
        output = r.std_out.decode('utf-8', errors='replace').strip()
        print(f"    Admin check result: '{output}'")
        return output.lower() == "true"

    def _check_smb_access(self):
        if not IMPACKET_AVAILABLE:
            return False
        test_smb = SMBTransport(self.target_ip, self.username, self.password, self.domain, self.lmhash, self.nthash)
        if test_smb.connect():
            test_smb.disconnect()
            return True
        return False

    # ---------- HTTP-сервер для больших файлов ----------
    def _ensure_http_server(self):
        print(f"{Fore.CYAN}[DEBUG] In _ensure_http_server: address='{self.http_listen_address}', port={self.http_port}{Style.RESET_ALL}")
        if self.is_admin and self.smb_available:
            return
        if not self.http_listen_address or not self.http_port:
            print(f"{Fore.YELLOW}[!] HTTP server not configured (missing address/port). Large files will use chunked fallback.{Style.RESET_ALL}")
            return

        project_root = Path(__file__).parent.parent.parent
        server_script = project_root / "tools" / "http_server.py"
        if not server_script.exists():
            print(f"{Fore.RED}[!] HTTP server script not found: {server_script}{Style.RESET_ALL}")
            return

        self.pid_file = project_root / "tools" / ".server.pid"

        if self._is_http_server_running():
            print(f"{Fore.GREEN}[+] HTTP server already running on {self.http_listen_address}:{self.http_port}{Style.RESET_ALL}")
            return

        print(f"{Fore.YELLOW}[*] Starting HTTP server on {self.http_listen_address}:{self.http_port} ...{Style.RESET_ALL}")
        try:
            self.http_server_process = subprocess.Popen(
                [sys.executable, str(server_script),
                 "--host", self.http_listen_address,
                 "--port", str(self.http_port),
                 "--pidfile", str(self.pid_file)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            time.sleep(1)
            if self._is_http_server_running():
                print(f"{Fore.GREEN}[+] HTTP server started (PID {self.http_server_process.pid}){Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] Failed to start HTTP server. Check {server_script}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error starting HTTP server: {e}{Style.RESET_ALL}")

    def _is_http_server_running(self):
        if self.pid_file and self.pid_file.exists():
            try:
                with open(self.pid_file, 'r') as f:
                    pid = int(f.read().strip())
                if psutil.pid_exists(pid):
                    try:
                        proc = psutil.Process(pid)
                        for conn in proc.connections(kind='inet'):
                            if conn.laddr.port == self.http_port and conn.status == 'LISTEN':
                                return True
                    except:
                        pass
            except:
                pass
        try:
            with socket.create_connection((self.http_listen_address, self.http_port), timeout=1):
                return True
        except:
            return False

    def stop_http_server(self):
        if not self.http_server_auto_stop:
            return
        if self.pid_file and self.pid_file.exists():
            try:
                with open(self.pid_file, 'r') as f:
                    pid = int(f.read().strip())
                if psutil.pid_exists(pid):
                    proc = psutil.Process(pid)
                    proc.terminate()
                    proc.wait(timeout=3)
                    print(f"{Fore.GREEN}[+] HTTP server stopped (PID {pid}){Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Could not stop HTTP server: {e}{Style.RESET_ALL}")
            finally:
                if self.pid_file.exists():
                    self.pid_file.unlink(missing_ok=True)

    # ---------- Загрузка файлов через WinRM+HTTP (старый способ) ----------
    def _upload_file(self, local_path, remote_path):
        file_size = os.path.getsize(local_path)
        if file_size > LARGE_FILE_THRESHOLD and self.http_listen_address and self.http_port:
            print(f"    Large file detected ({file_size // 1024} KB). Using HTTP server...")
            if self._download_via_http_server(local_path, remote_path):
                return True
            print(f"    {Fore.YELLOW}[!] HTTP download failed, falling back to chunked.{Style.RESET_ALL}")
        return self._upload_file_chunked(local_path, remote_path)

    def _download_via_http_server(self, local_path, remote_path):
        filename = os.path.basename(local_path)
        url = f"http://{self.http_listen_address}:{self.http_port}/{filename}"
        print(f"      URL: {url}")

        test_cmd = f"Test-NetConnection -ComputerName {self.http_listen_address} -Port {self.http_port} -InformationLevel Quiet"
        r_test = self._run_ps(test_cmd)
        if r_test.std_out.decode('utf-8', errors='replace').strip() == "True":
            print(f"      Port {self.http_port} is reachable from target.")
        else:
            print(f"      Port {self.http_port} is NOT reachable from target. HTTP download will likely fail.")

        ps_cmd = f"""
        try {{
            $webClient = New-Object System.Net.WebClient
            $webClient.Proxy = $null
            $webClient.DownloadFile('{url}', '{remote_path}')
            Write-Output "HTTP_DOWNLOAD_SUCCESS"
        }} catch {{
            Write-Error "WebClient error: $($_.Exception.Message)"
        }}
        """
        r = self._run_ps(ps_cmd)
        output = r.std_out.decode('utf-8', errors='replace')
        err = r.std_err.decode('utf-8', errors='replace')
        if "HTTP_DOWNLOAD_SUCCESS" in output:
            print(f"    {Fore.GREEN}[✓]{Style.RESET_ALL} Downloaded via HTTP (WebClient): {filename}")
            return True
        else:
            print(f"      WebClient failed: {err.strip() or output.strip()}")
            ps_cmd2 = f"""
            try {{
                $null = Invoke-WebRequest -Uri '{url}' -OutFile '{remote_path}' -UseBasicParsing -ErrorAction Stop
                Write-Output "HTTP_DOWNLOAD_SUCCESS"
            }} catch {{
                Write-Error "Invoke-WebRequest error: $($_.Exception.Message)"
            }}
            """
            r2 = self._run_ps(ps_cmd2)
            output2 = r2.std_out.decode('utf-8', errors='replace')
            err2 = r2.std_err.decode('utf-8', errors='replace')
            if "HTTP_DOWNLOAD_SUCCESS" in output2:
                print(f"    {Fore.GREEN}[✓]{Style.RESET_ALL} Downloaded via HTTP (Invoke-WebRequest): {filename}")
                return True
            else:
                print(f"      Invoke-WebRequest also failed: {err2.strip() or output2.strip()}")
                return False

    def _upload_file_chunked(self, local_path, remote_path, initial_chunk_size=200):
        try:
            with open(local_path, 'rb') as f:
                b64_data = base64.b64encode(f.read()).decode('ascii')
            parent_dir = os.path.dirname(remote_path)
            self._ensure_dir(parent_dir)
            self._run_ps(f"Remove-Item -Path '{remote_path}' -Force -ErrorAction SilentlyContinue")
            total_len = len(b64_data)
            chunk_size = initial_chunk_size
            i = 0
            print(f"    Chunked uploading {os.path.basename(local_path)} ({total_len} chars)...")
            while i < total_len:
                chunk = b64_data[i:i+chunk_size]
                chunk_escaped = chunk.replace("'", "''")
                ps_cmd = f"[System.IO.File]::AppendAllText('{remote_path}', '{chunk_escaped}')"
                r = self._run_ps(ps_cmd)
                if r.status_code != 0:
                    err_text = r.std_err.decode('utf-8', errors='replace').lower()
                    if "command line is too long" in err_text and chunk_size > 20:
                        chunk_size = max(20, chunk_size // 2)
                        print(f"      Reducing chunk size to {chunk_size}")
                        continue
                    else:
                        raise Exception(f"Chunk failed: {err_text[:200]}")
                i += chunk_size
                percent = int(100 * i / total_len)
                print(f"      {percent}% ({i}/{total_len})", end='\r')
                time.sleep(0.05)
            print()
            decode_cmd = f"$bytes = [Convert]::FromBase64String((Get-Content '{remote_path}' -Raw)); [IO.File]::WriteAllBytes('{remote_path}', $bytes)"
            r = self._run_ps(decode_cmd)
            if r.status_code == 0:
                print(f"    {Fore.GREEN}[✓]{Style.RESET_ALL} Uploaded: {os.path.basename(local_path)}")
                return True
            else:
                print(f"    {Fore.RED}[✗]{Style.RESET_ALL} Decode failed")
                return False
        except Exception as e:
            print(f"    {Fore.RED}[✗]{Style.RESET_ALL} Chunked error: {e}")
            return False

    def _upload_dir_ps(self, local_dir, remote_dir):
        local_dir = os.path.abspath(local_dir)
        if not os.path.exists(local_dir):
            print(f"    {Fore.RED}[!] Local path not found: {local_dir}{Style.RESET_ALL}")
            return
        for root, dirs, files in os.walk(local_dir):
            rel = os.path.relpath(root, local_dir).replace(os.sep, '\\')
            curr_remote = f"{remote_dir}\\{rel}" if rel != '.' else remote_dir
            self._ensure_dir(curr_remote)
            for fname in files:
                local_file = os.path.join(root, fname)
                remote_file = f"{curr_remote}\\{fname}"
                self._upload_file(local_file, remote_file)

    # ---------- SMB-деплой ----------
    def _deploy_via_smb(self, local_project_root):
        print(f"{Fore.GREEN}[+] Using SMB transport (Impacket){Style.RESET_ALL}")
        self.smb_transport = SMBTransport(self.target_ip, self.username, self.password or '', self.domain, self.lmhash, self.nthash)
        if not self.smb_transport.connect():
            print(f"{Fore.YELLOW}[!] SMB connection failed.{Style.RESET_ALL}")
            return False

        if not self.smb_transport.create_directory(self.remote_base):
            print(f"{Fore.YELLOW}[!] Cannot create base directory via SMB.{Style.RESET_ALL}")
            self.smb_transport.disconnect()
            return False

        self.smb_transport.create_directory(f"{self.remote_base}\\runner")
        self.smb_transport.create_directory(f"{self.remote_base}\\modules")
        self.smb_transport.create_directory(f"{self.remote_base}\\output")

        runner_src = os.path.join(local_project_root, "runner", "runner.ps1")
        if os.path.exists(runner_src):
            if not self.smb_transport.upload_file(runner_src, f"{self.remote_base}\\runner\\runner.ps1"):
                print(f"{Fore.RED}[!] Failed to upload runner.ps1 via SMB.{Style.RESET_ALL}")
                self.smb_transport.disconnect()
                return False
        else:
            print(f"{Fore.RED}[!] runner.ps1 not found at {runner_src}{Style.RESET_ALL}")
            self.smb_transport.disconnect()
            return False

        modules_src = os.path.join(local_project_root, "modules")
        if os.path.exists(modules_src):
            for root, dirs, files in os.walk(modules_src):
                rel = os.path.relpath(root, modules_src).replace(os.sep, '\\')
                curr_remote = f"{self.remote_base}\\modules\\{rel}" if rel != '.' else f"{self.remote_base}\\modules"
                self.smb_transport.create_directory(curr_remote)
                for fname in files:
                    local_file = os.path.join(root, fname)
                    remote_file = f"{curr_remote}\\{fname}"
                    if not self.smb_transport.upload_file(local_file, remote_file):
                        print(f"{Fore.YELLOW}[!] Failed to upload {fname} via SMB, but continuing...{Style.RESET_ALL}")

        print(f"{Fore.GREEN}[+] SMB deployment complete.{Style.RESET_ALL}")
        return True

    # ---------- WinRM+HTTP деплой ----------
    def _deploy_via_winrm_http(self, local_project_root):
        print(f"{Fore.YELLOW}[*] Deploying payload via WinRM...{Style.RESET_ALL}")
        self._ensure_dir(self.remote_base)
        self._ensure_dir(f"{self.remote_base}\\runner")
        self._ensure_dir(f"{self.remote_base}\\modules")
        self._ensure_dir(f"{self.remote_base}\\output")

        runner_src = os.path.join(local_project_root, "runner", "runner.ps1")
        if os.path.exists(runner_src):
            self._upload_file(runner_src, f"{self.remote_base}\\runner\\runner.ps1")
        else:
            print(f"{Fore.RED}[!] runner.ps1 not found at {runner_src}{Style.RESET_ALL}")

        modules_src = os.path.join(local_project_root, "modules")
        if os.path.exists(modules_src):
            self._upload_dir_ps(modules_src, f"{self.remote_base}\\modules")

        print(f"{Fore.GREEN}[+] WinRM deployment complete.{Style.RESET_ALL}")

    # ---------- Сохранение информации о правах ----------
    def _save_privilege_info(self):
        privilege_data = {
            "is_admin": self.is_admin,
            "transport": "SMB" if self.smb_available else "WinRM+HTTP",
            "user": self.username
        }
        json_str = json.dumps(privilege_data, indent=2)
        json_escaped = json_str.replace("'", "''")
        ps_cmd = f"$json = '{json_escaped}' | ConvertFrom-Json; $json | ConvertTo-Json -Depth 5 | Out-File '{self.remote_base}\\output\\privilege.json' -Encoding UTF8"
        self._run_ps(ps_cmd)

    # ---------- Основной метод деплоя ----------
    def deploy(self, local_project_root):
        # Проверяем права администратора
        self.is_admin = self._check_admin_rights()
        if self.is_admin:
            self.smb_available = self._check_smb_access()
            if self.smb_available and IMPACKET_AVAILABLE:
                print(f"{Fore.GREEN}[+] Admin rights and SMB available. Using SMB for fast deployment.{Style.RESET_ALL}")
                self._save_privilege_info()
                if self._deploy_via_smb(local_project_root):
                    return
                else:
                    print(f"{Fore.YELLOW}[!] SMB deployment failed, falling back to WinRM+HTTP.{Style.RESET_ALL}")
                    self.smb_available = False
                    if self.smb_transport:
                        self.smb_transport.disconnect()
                        self.smb_transport = None
            else:
                if not IMPACKET_AVAILABLE:
                    print(f"{Fore.YELLOW}[!] Impacket not installed. Install with: pip install impacket{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[!] Admin rights but SMB unavailable. Check firewall/port 445 and LocalAccountTokenFilterPolicy.{Style.RESET_ALL}")

        # Если не админ или SMB недоступен, используем WinRM+HTTP
        print(f"{Fore.YELLOW}[!] Not admin or SMB unavailable. Using WinRM+HTTP deployment.{Style.RESET_ALL}")
        self._save_privilege_info()
        self._ensure_http_server()
        self._deploy_via_winrm_http(local_project_root)

    # ---------- Выполнение модулей ----------
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

    # ---------- Скачивание архива ----------
    def retrieve_archive(self):
        print(f"{Fore.YELLOW}[*] Retrieving archive...{Style.RESET_ALL}")
        if self.is_admin and self.smb_available and self.smb_transport:
            return self._retrieve_archive_smb()
        else:
            return self._retrieve_archive_winrm()

    def _retrieve_archive_smb(self):
        find_cmd = f"Get-ChildItem '{self.remote_base}\\output' -Filter '*.zip' | Sort LastWriteTime -Descending | Select -First 1 -Expand FullName"
        r = self._run_ps(find_cmd)
        zip_path = r.std_out.decode('utf-8', errors='replace').strip()
        if not zip_path or "Get-ChildItem" in zip_path:
            print(f"{Fore.RED}[!] No archive found.{Style.RESET_ALL}")
            return False
        local_zip = os.path.join("output", os.path.basename(zip_path))
        os.makedirs("output", exist_ok=True)
        if self.smb_transport.download_file(zip_path, local_zip):
            print(f"{Fore.GREEN}[+] Downloaded via SMB: {local_zip}{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.RED}[!] SMB download failed, trying WinRM...{Style.RESET_ALL}")
            return self._retrieve_archive_winrm()

    def _retrieve_archive_winrm(self):
        find_cmd = f"Get-ChildItem '{self.remote_base}\\output' -Filter '*.zip' | Sort LastWriteTime -Descending | Select -First 1 -Expand FullName"
        r = self._run_ps(find_cmd)
        zip_path = r.std_out.decode('utf-8', errors='replace').strip()
        if not zip_path or "Get-ChildItem" in zip_path:
            print(f"{Fore.RED}[!] No archive found.{Style.RESET_ALL}")
            return False
        read_cmd = f"[Convert]::ToBase64String([IO.File]::ReadAllBytes('{zip_path}'))"
        r = self._run_ps(read_cmd)
        b64_content = r.std_out.decode('utf-8', errors='replace').strip()
        local_zip = os.path.join("output", os.path.basename(zip_path))
        os.makedirs("output", exist_ok=True)
        with open(local_zip, 'wb') as f:
            f.write(base64.b64decode(b64_content))
        print(f"{Fore.GREEN}[+] Downloaded via WinRM: {local_zip}{Style.RESET_ALL}")
        return True

    # ---------- Очистка ----------
    def cleanup(self):
        print(f"{Fore.YELLOW}[*] Cleaning up...{Style.RESET_ALL}")
        # Закрываем runspace
        try:
            self.runspace.__exit__(None, None, None)
        except:
            pass
        # Удаляем временную папку на удалённой машине
        self._run_ps(f"Remove-Item '{self.remote_base}' -Recurse -Force -ErrorAction SilentlyContinue")
        print(f"{Fore.GREEN}[+] Cleanup complete.{Style.RESET_ALL}")
        if self.smb_transport:
            self.smb_transport.disconnect()
        self.stop_http_server()