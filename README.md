# ARFSearch v2 (WinRM)

ARFSearch v2 is an artifact-collection tool focused on Windows endpoint collection using WinRM and SMB transports. This repository contains a CLI for managing targets, deploying a PowerShell runner on remote hosts, and retrieving collected archives.

## Highlights (changes)
- Targets format: `config/targets.json` now uses named targets (top-level key is `target_name`). Each entry includes `ip`, `user`, `password`, `proto` and optional `lmhash`/`nthash` for NTLM hash auth.
- NTLM hash support: You can provide NTLM hashes (LM:NT or NT only) when adding targets. The tool uses Impacket (if installed) to authenticate via SMB using LM/NT hash (pass-the-hash style). WinRM still requires a plaintext password.
- SMB fallback: If WinRM session cannot be established (or when only hashes were provided), the tool will try SMB deployment using Impacket. This enables deploying without knowledge of the plaintext password on hosts that accept SMB auth.
- HTTP server for large files: the CLI can start a local HTTP server to serve large files to the target for download during WinRM deployment; this is configured via `config/settings.json` (http_listen_address, http_port, http_server_auto_stop).
- Backwards compatibility: older `targets.json` file format (IP keys) is automatically migrated to the new named-target format on load.

## Usage
1. Ensure dependencies are installed (recommended inside virtualenv):

```sh
pip install -r requirements.txt
# For SMB hash auth (optional):
pip install impacket
```

2. Edit `config/settings.json` for HTTP server options if needed. If you want target machines to reach your HTTP server, set `http_listen_address` to an interface reachable by targets or `0.0.0.0`.

3. Add targets via the CLI. You can provide an NTLM hash instead of a password:

- Start CLI:

```sh
python cli/cli.py
```

- Add target: supply IP, username, and either password or NTLM hash (format `LM:NTHASH` or just `NTHASH`). Optionally set a target name.

4. Connect: choose target by number or name. If WinRM password is provided the tool will try WinRM; if only hash provided it will try SMB using Impacket.

## Files of interest
- `cli/cli.py` - CLI entrypoint, target management and connect flow.
- `cli/transport/winrm_transport.py` - WinRM transport, deploy & retrieval logic. Handles WinRM + HTTP and SMB fallback.
- `cli/transport/smb_transport.py` - SMB helper using Impacket; supports lmhash/nthash.
- `tools/http_server.py` - lightweight HTTP server used to serve large files to target.
- `runner/runner.ps1` and `modules/` - code deployed to the target for artifact collection.
- `config/settings.json`, `config/targets.json` - runtime configuration and saved targets.

## Security notes
- `config/targets.json` may contain sensitive information (passwords or NTLM hashes). Keep it out of version control (it is in `.gitignore`) and protect the file.

## Troubleshooting
- If you see `No route to host` when connecting: verify the target IP and network connectivity (ping/nc/traceroute).
- If authentication fails but SMB works for an admin account, try using NTLM hash + SMB path.

## Contributing
Open issues or pull requests for feature suggestions or fixes.

---
Updated to reflect code changes made on or around 2026-06-01.
