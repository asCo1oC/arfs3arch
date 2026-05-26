import sys, os, json, getpass
from pathlib import Path
from colorama import init, Fore, Style
import atexit

init(autoreset=True)

try:
    from transport.winrm_transport import WinRMTransport
except ImportError as e:
    print(f"{Fore.RED}[!] Failed to import WinRMTransport: {e}{Style.RESET_ALL}")
    sys.exit(1)


class CLI:
    def __init__(self):
        self.targets_file = Path("config/targets.json")
        self.settings_file = Path("config/settings.json")
        self.targets = self.load_targets()
        self.settings = self.load_settings()
        self.session = None
        # Регистрируем остановку HTTP-сервера один раз
        atexit.register(self._cleanup_http_server)

    def load_targets(self):
        if self.targets_file.exists():
            try:
                return json.loads(self.targets_file.read_text())
            except json.JSONDecodeError:
                print(f"{Fore.RED}[!] Corrupted targets.json. Resetting.{Style.RESET_ALL}")
                return {}
        return {}

    def load_settings(self):
        if self.settings_file.exists():
            try:
                return json.loads(self.settings_file.read_text())
            except json.JSONDecodeError:
                print(f"{Fore.RED}[!] Corrupted settings.json. Using defaults.{Style.RESET_ALL}")
        return {}

    def save_targets(self):
        self.targets_file.parent.mkdir(exist_ok=True)
        self.targets_file.write_text(json.dumps(self.targets, indent=2))

    def main_loop(self):
        print(f"{Fore.CYAN}=== Artifact Collector CLI (MVP) ==={Style.RESET_ALL}")
        while True:
            print(f"\n{Fore.CYAN}[MAIN MENU]{Style.RESET_ALL}")
            print("  1. List targets")
            print("  2. Add target")
            print("  3. Connect & Operate")
            print("  q. Quit")

            choice = input(f"{Fore.YELLOW}> {Style.RESET_ALL}").strip().lower()
            if choice == '1':
                self.list_targets()
            elif choice == '2':
                self.add_target()
            elif choice == '3':
                self.connect()
            elif choice == 'q':
                break

    def list_targets(self):
        print(f"\n{Fore.CYAN}Saved Targets:{Style.RESET_ALL}")
        if not self.targets:
            print("  (Empty)")
            return
        for idx, (ip, data) in enumerate(self.targets.items(), 1):
            print(f"  {idx}. {ip} | User: {data.get('user', 'unknown')} | Proto: {data.get('proto', 'winrm')}")

    def add_target(self):
        ip = input("IP/Hostname: ").strip()
        if not ip:
            return
        user = input("Username: ").strip()
        if not user:
            return
        passwd = getpass.getpass("Password: ")
        proto = input("Protocol (ssh/winrm) [winrm]: ").strip().lower() or 'winrm'
        if proto not in ['ssh', 'winrm']:
            proto = 'winrm'

        self.targets[ip] = {'user': user, 'password': passwd, 'proto': proto}
        self.save_targets()
        print(f"{Fore.GREEN}[+] Target {ip} added ({proto}){Style.RESET_ALL}")

    def connect(self):
        if not self.targets:
            print(f"{Fore.RED}[!] No targets configured. Please add one first.{Style.RESET_ALL}")
            return

        self.list_targets()
        choice = input(f"\n{Fore.YELLOW}Select target (number or IP): {Style.RESET_ALL}").strip()

        target_ip = None
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(self.targets):
                target_ip = list(self.targets.keys())[idx - 1]
        elif choice in self.targets:
            target_ip = choice

        if not target_ip:
            print(f"{Fore.RED}[!] Invalid selection.{Style.RESET_ALL}")
            return

        data = self.targets[target_ip]
        proto = data.get('proto', 'winrm')

        try:
            print(f"{Fore.YELLOW}[*] Connecting to {target_ip} via {proto.upper()}...{Style.RESET_ALL}")
            if proto == 'winrm':
                http_addr = self.settings.get("http_listen_address", "")
                http_port = self.settings.get("http_port", 0)
                http_auto_stop = self.settings.get("http_server_auto_stop", False)
                self.session = WinRMTransport(
                    target_ip, data['user'], data['password'],
                    http_listen_address=http_addr,
                    http_port=http_port,
                    http_server_auto_stop=http_auto_stop
                )
            else:
                print(f"{Fore.RED}[!] SSH transport not implemented yet.{Style.RESET_ALL}")
                return

            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.session.deploy(project_root)
            self.remote_menu()
        except Exception as e:
            print(f"{Fore.RED}[!] Connection Failed: {e}{Style.RESET_ALL}")
            self.session = None

    def _cleanup_http_server(self):
        if self.session:
            self.session.stop_http_server()

    def remote_menu(self):
        while self.session:
            print(f"\n{Fore.CYAN}=== REMOTE SESSION ==={Style.RESET_ALL}")
            print("  1. Run logs module")
            print("  2. Run recent module")
            print("  3. Run browser module")
            print("  4. Run ALL modules")
            print("  5. Disconnect & Cleanup")

            cmd = input(f"{Fore.YELLOW}Choice: {Style.RESET_ALL}").strip()
            if cmd == '1':
                self.session.run_module("run logs")
            elif cmd == '2':
                self.session.run_module("run recent")
            elif cmd == '3':
                self.session.run_module("run browser")
            elif cmd == '4':
                self.session.run_module("collect all")
            elif cmd == '5':
                self.session.cleanup()
                self.session = None
                break
            else:
                print(f"{Fore.RED}[!] Invalid choice.{Style.RESET_ALL}")
                continue

            self.session.retrieve_archive()


if __name__ == "__main__":
    try:
        CLI().main_loop()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Exiting.{Style.RESET_ALL}")