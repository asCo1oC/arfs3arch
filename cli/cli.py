#!/usr/bin/env python3
# cli/cli.py - Operator CLI for Windows Artifact Collector
import os, sys, json, uuid, getpass, time
from pathlib import Path
import paramiko
from colorama import init, Fore, Style
init(autoreset=True)

class TargetStore:
    CONFIG = Path("config/targets.json")
    def __init__(self):
        self.CONFIG.parent.mkdir(exist_ok=True)
        self.targets = self._load()
    def _load(self):
        return json.loads(self.CONFIG.read_text()) if self.CONFIG.exists() else {}
    def save(self):
        self.CONFIG.write_text(json.dumps(self.targets, indent=2))
    def add(self, host, user, passwd):
        self.targets[host] = {"user": user, "password": passwd}
        self.save()
        print(f"{Fore.GREEN}[+] Target {host} saved.{Style.RESET_ALL}")
    def get(self, host): return self.targets.get(host)
    def list(self):
        if not self.targets: print("  (empty)")
        for h, t in self.targets.items(): print(f"  {Fore.CYAN}{h}{Style.RESET_ALL} | user: {t['user']}")

class RemoteSession:
    def __init__(self, host, user, passwd):
        print(f"{Fore.YELLOW}[*] Connecting to {host}:22 ...{Style.RESET_ALL}")
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(host, port=22, username=user, password=passwd, timeout=15)
        self.sftp = self.client.open_sftp()
        
        # Используем пользовательский %TEMP% для обхода проблем с правами
        self.remote_base = f"C:/Users/{user}/AppData/Local/Temp/collector_{uuid.uuid4().hex[:8]}"
        self._deploy()

    def _ensure_remote_dir(self, remote_dir):
        """Рекурсивное создание директорий на удалённом хосте через SFTP"""
        remote_dir = remote_dir.replace("\\", "/").rstrip("/")
        parts = remote_dir.split("/")
        curr = ""
        for p in parts:
            if p:
                curr = f"{curr}/{p}" if curr else f"/{p}"
                try: self.sftp.stat(curr)
                except IOError:
                    try: self.sftp.mkdir(curr)
                    except: pass

    def _upload_dir(self, local_path, remote_path):
        local_path = Path(local_path).resolve()
        if not local_path.exists():
            print(f"    {Fore.RED}[!] Local path not found: {local_path}{Style.RESET_ALL}")
            return
            
        remote_path = remote_path.replace("\\", "/").rstrip("/")
        
        for root, dirs, files in os.walk(local_path):
            rel = str(Path(root).relative_to(local_path)).replace("\\", "/")
            current_remote = f"{remote_path}/{rel}" if rel != "." else remote_path
            
            # Гарантируем существование директории
            self._ensure_remote_dir(current_remote)
            
            for fname in files:
                local_file = os.path.join(root, fname)
                remote_file = f"{current_remote}/{fname}"
                try:
                    self.sftp.put(local_file, remote_file)
                except Exception as e:
                    print(f"    {Fore.RED}[!] Upload failed: {fname} -> {e}{Style.RESET_ALL}")
                    raise e

    def _deploy(self):
        print(f"{Fore.YELLOW}[*] Deploying payload to {self.remote_base} ...{Style.RESET_ALL}")
        
        # 1. Надёжное создание структуры через PowerShell
        ps_cmd = (f'New-Item -ItemType Directory -Force -Path "{self.remote_base}/runner", '
                  f'"{self.remote_base}/modules", "{self.remote_base}/output" | Out-Null')
        self.exec_ps(ps_cmd)
        
        # 2. Загрузка файлов
        project_root = Path(__file__).resolve().parent.parent
        self._upload_dir(project_root / "runner", f"{self.remote_base}/runner")
        self._upload_dir(project_root / "modules", f"{self.remote_base}/modules")
        
        print(f"{Fore.GREEN}[+] Deployment complete.{Style.RESET_ALL}")

    def exec_ps(self, cmd, timeout=900):
        full = f'powershell -NoProfile -ExecutionPolicy Bypass -Command "{cmd}"'
        stdin, stdout, stderr = self.client.exec_command(full, timeout=timeout)
        return stdout.read().decode("utf-8", errors="replace"), \
               stderr.read().decode("utf-8", errors="replace"), \
               stdout.channel.recv_exit_status()

    def run_module(self, cmd):
        # Используем полный путь и прямой вызов через -File
        remote_script = f"{self.remote_base}\\runner\\runner.ps1"
        # Экранирование кавычек для PowerShell
        ps_cmd = f"powershell -NoProfile -ExecutionPolicy Bypass -File \"{remote_script}\" {cmd}"
        
        print(f"\n{Fore.CYAN}[*] Executing: {cmd} ...{Style.RESET_ALL}")
        stdin, stdout, stderr = self.client.exec_command(ps_cmd, timeout=900)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        code = stdout.channel.recv_exit_status()
        
        print(out)
        if err.strip(): 
            # Фильтруем ложные срабатывания консольной кодировки
            if "DirectoryNotFoundException" in err or "Не удается найти часть пути" in err:
                print(f"{Fore.RED}[!] Critical Path Error: {err}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[i] stderr: {err}{Style.RESET_ALL}")
                
        if code == 0: 
            self._download_archive()
        else: 
            print(f"{Fore.RED}[!] Execution failed (exit {code}){Style.RESET_ALL}")

    def _download_archive(self):
        print(f"{Fore.YELLOW}[*] Searching for archive...{Style.RESET_ALL}")
        # Ищем в папке output, которая создаётся runner-ом на уровень выше runner/
        find_cmd = f"Get-ChildItem '{self.remote_base}/output' -Filter '*.zip' | Sort LastWriteTime -Descending | Select -First 1 -Expand FullName"
        out, _, _ = self.exec_ps(find_cmd)
        zip_path = out.strip().replace("\\", "/")
        
        if not zip_path or "Get-ChildItem" in zip_path:
            print(f"{Fore.RED}[!] No archive found in {self.remote_base}/output{Style.RESET_ALL}")
            # Debug: покажем, что вообще есть в папке сбора
            dbg, _, _ = self.exec_ps(f"Get-ChildItem '{self.remote_base}' -Recurse | Select-Object FullName")
            print(f"{Fore.YELLOW}[DEBUG] Remote structure:{Style.RESET_ALL}\n{dbg}")
            return
            
        local_zip = Path("output") / Path(zip_path).name
        local_zip.parent.mkdir(exist_ok=True)
        self.sftp.get(zip_path, str(local_zip))
        print(f"{Fore.GREEN}[+] Downloaded: {local_zip}{Style.RESET_ALL}")

    def cleanup(self):
        if not self.client: return
        print(f"{Fore.YELLOW}[*] Cleaning up remote files...{Style.RESET_ALL}")
        self.exec_ps(f"Remove-Item '{self.remote_base}' -Recurse -Force -ErrorAction SilentlyContinue")
        self.sftp.close(); self.client.close()
        self.client = self.sftp = self.remote_base = None
        print(f"{Fore.GREEN}[+] Disconnected & cleaned.{Style.RESET_ALL}")
class CLI:
    def __init__(self):
        self.store = TargetStore()
        self.session = None

    def _remote_menu(self):
        while self.session:
            print(f"\n{Fore.CYAN}=== REMOTE SESSION ({self.session.remote_base.split('/')[-1]}) ==={Style.RESET_ALL}")
            print("  1. Run browser module")
            print("  2. Run logs module")
            print("  3. Run recent module")
            print("  4. Run ALL modules")
            print("  5. Disconnect & Cleanup")
            c = input(f"{Fore.YELLOW}Choice: {Style.RESET_ALL}").strip()
            if c in ["1","2","3","4"]:
                self.session.run_module(["run browser","run logs","run recent","collect all"][int(c)-1])
            elif c == "5": break
            else: print(f"{Fore.RED}[!] Invalid choice.{Style.RESET_ALL}"); continue

            stay = input(f"\n{Fore.YELLOW}Stay connected? [y/N]: {Style.RESET_ALL}").strip().lower()
            if stay != "y":
                self.session.cleanup(); self.session = None; break

    def main_loop(self):
        print(f"{Fore.CYAN}=== Windows Artifact Collector CLI (MVP) ==={Style.RESET_ALL}")
        while True:
            print(f"\n{Fore.CYAN}[MAIN MENU]{Style.RESET_ALL}")
            print("  1. List targets")
            print("  2. Add target (host user password)")
            print("  3. Connect & Operate")
            print("  q. Quit")
            c = input(f"{Fore.YELLOW}> {Style.RESET_ALL}").strip()
            if c == "1": self.store.list()
            elif c == "2":
                parts = input("Format: <host> <user> <password>: ").split()
                if len(parts) == 3: self.store.add(*parts)
            elif c == "3":
                host = input("Target IP/Hostname: ").strip()
                t = self.store.get(host)
                user = t["user"] if t else input("Username: ")
                passwd = t["password"] if t else getpass.getpass("Password: ")
                try:
                    self.session = RemoteSession(host, user, passwd)
                    self._remote_menu()
                except Exception as e:
                    print(f"{Fore.RED}[!] Connection/Deploy failed: {e}{Style.RESET_ALL}")
                    if self.session: self.session.cleanup(); self.session = None
            elif c.lower() == "q": break

if __name__ == "__main__":
    try: CLI().main_loop()
    except KeyboardInterrupt: print(f"\n{Fore.YELLOW}Exiting.{Style.RESET_ALL}")
    except Exception as e: print(f"{Fore.RED}[FATAL] {e}{Style.RESET_ALL}")
