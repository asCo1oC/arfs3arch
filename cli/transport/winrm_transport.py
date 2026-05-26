import os
import uuid
import base64
import time
import socket
import subprocess
import shutil
import sys
import psutil
import winrm
from colorama import Fore, Style
from pathlib import Path

LARGE_FILE_THRESHOLD = 500 * 1024  # 500 KB


class WinRMTransport:
    def __init__(self, host, user, password, domain='', http_listen_address='', http_port=0, http_server_auto_stop=False):
        self.http_listen_address = http_listen_address
        self.http_port = http_port
        self.http_server_auto_stop = http_server_auto_stop
        self.http_server_process = None
        self.pid_file = None

        print(f"{Fore.YELLOW}[*] Connecting to {host} via WinRM...{Style.RESET_ALL}")
        self.session = winrm.Session(
            f'http://{host}:5985/wsman',
            auth=(f'{domain}\\{user}' if domain else user, password),
            transport='ntlm',
            server_cert_validation='ignore'
        )

        result = self._run_ps("$env:TEMP")
        real_temp = result.std_out.decode('utf-8', errors='replace').strip()
        if not real_temp:
            real_temp = "C:\\Windows\\Temp"
        self.remote_base = f"{real_temp}\\collector_{uuid.uuid4().hex[:8]}"
        print(f"{Fore.GREEN}[+] Connected. Staging dir: {self.remote_base}{Style.RESET_ALL}")

        self._ensure_http_server()

    def _run_ps(self, cmd):
        safe_cmd = (
            "[Console]::InputEncoding = [Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
            "$PSDefaultParameterValues['*:Encoding'] = 'utf8'; "
            f"{cmd}"
        )
        return self.session.run_ps(safe_cmd)

    def _ensure_dir(self, path):
        cmd = f"if (-not (Test-Path -Path '{path}')) {{ New-Item -ItemType Directory -Force -Path '{path}' | Out-Null }}"
        r = self._run_ps(cmd)
        return r.status_code == 0

    # ---------- HTTP server management ----------
    def _ensure_http_server(self):
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

    # ---------- File transfer methods ----------
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

        # WebClient without proxy
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

            # Fallback: Invoke-WebRequest
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

    # ---------- Public API ----------
    def deploy(self, local_project_root):
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

        print(f"{Fore.GREEN}[+] Deployment complete.{Style.RESET_ALL}")

    def run_module(self, cmd):
        runner_path = f"{self.remote_base}\\runner\\runner.ps1"
        ps_cmd = f'powershell -NoProfile -ExecutionPolicy Bypass -File "{runner_path}" {cmd}'
        print(f"{Fore.CYAN}[*] Executing: {cmd} ...{Style.RESET_ALL}")
        r = self.session.run_ps(ps_cmd)
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

        read_cmd = f"[Convert]::ToBase64String([IO.File]::ReadAllBytes('{zip_path}'))"
        r = self._run_ps(read_cmd)
        b64_content = r.std_out.decode('utf-8', errors='replace').strip()
        local_zip = os.path.join("output", os.path.basename(zip_path))
        os.makedirs("output", exist_ok=True)
        with open(local_zip, 'wb') as f:
            f.write(base64.b64decode(b64_content))
        print(f"{Fore.GREEN}[+] Downloaded: {local_zip}{Style.RESET_ALL}")
        return True

    def cleanup(self):
        print(f"{Fore.YELLOW}[*] Cleaning up...{Style.RESET_ALL}")
        self._run_ps(f"Remove-Item '{self.remote_base}' -Recurse -Force -ErrorAction SilentlyContinue")
        print(f"{Fore.GREEN}[+] Cleanup complete.{Style.RESET_ALL}")
        self.stop_http_server()