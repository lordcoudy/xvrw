from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import time
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


WGCF_VERSION = "2.2.31"
WGCF_ASSET = f"wgcf_{WGCF_VERSION}_linux_amd64"
WGCF_URL = (
    f"https://github.com/ViRb3/wgcf/releases/download/v{WGCF_VERSION}/{WGCF_ASSET}"
)

DEFAULT_PORT = 443
DEFAULT_SNI = "www.microsoft.com"
DEFAULT_DEST = "www.microsoft.com:443"
DEFAULT_FINGERPRINT = "chrome"
DEFAULT_FLOW = "xtls-rprx-vision"
DEFAULT_SHORT_ID_BYTES = 8
DEFAULT_WARP_ALLOWED_IPS = "162.159.192.0/24"
DEFAULT_WARP_ADDRESS = "172.16.0.2/32"

STATE_DIR = Path("/etc/xray-warp")
STATE_PATH = STATE_DIR / "state.json"
XRAY_CONFIG_PATH = Path("/usr/local/etc/xray/config.json")
WIREGUARD_DIR = Path("/etc/wireguard")
WGCF_STRIPPED_PATH = WIREGUARD_DIR / "wgcf.conf"
WGCF_SERVICE_PATH = Path("/etc/systemd/system/xray-warp-wgcf.service")
WGCF_BIN_PATH = Path("/usr/local/bin/wgcf")


class XrayWarpError(RuntimeError):
    """Raised for expected CLI failures."""


@dataclass(frozen=True)
class CommandResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str


class Runner:
    def run(
        self,
        args: list[str],
        *,
        cwd: Path | None = None,
        check: bool = True,
        input_text: str | None = None,
    ) -> CommandResult:
        try:
            proc = subprocess.run(
                args,
                cwd=str(cwd) if cwd else None,
                input=input_text,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        except FileNotFoundError as exc:
            result = CommandResult(args, 127, "", str(exc))
            if check:
                raise XrayWarpError(format_command_failure(result)) from exc
            return result
        result = CommandResult(args, proc.returncode, proc.stdout, proc.stderr)
        if check and proc.returncode != 0:
            raise XrayWarpError(format_command_failure(result))
        return result


def format_command_failure(result: CommandResult) -> str:
    stderr = result.stderr.strip()
    stdout = result.stdout.strip()
    detail = stderr or stdout or "no output"
    return f"Command failed ({result.returncode}): {' '.join(result.args)}\n{detail}"


def require_root() -> None:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise XrayWarpError("This command must be run as root.")


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def validate_name(name: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name):
        raise XrayWarpError(
            "Client name must be 1-64 chars: letters, numbers, dot, underscore, dash."
        )
    return name


def validate_server(server: str) -> str:
    if not server or any(ch.isspace() for ch in server):
        raise XrayWarpError("Server must be an IP address or DNS name without spaces.")
    try:
        ipaddress.ip_address(server)
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", server) or "." not in server:
            raise XrayWarpError("Server must be a valid IP address or DNS name.")
    return server


def new_uuid() -> str:
    return str(uuid.uuid4())


def new_short_id() -> str:
    return secrets.token_hex(DEFAULT_SHORT_ID_BYTES)


def load_state(path: Path = STATE_PATH) -> dict[str, Any]:
    if not path.exists():
        raise XrayWarpError(f"State file not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def save_state(state: dict[str, Any], path: Path = STATE_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def user_by_name(state: dict[str, Any], name: str) -> dict[str, str]:
    for user in state.get("users", []):
        if user.get("name") == name:
            return user
    raise XrayWarpError(f"Client not found: {name}")


def add_state_user(state: dict[str, Any], name: str, user_id: str | None = None) -> dict[str, str]:
    validate_name(name)
    if any(user.get("name") == name for user in state.get("users", [])):
        raise XrayWarpError(f"Client already exists: {name}")
    user = {"name": name, "uuid": user_id or new_uuid(), "created_at": now_iso()}
    state.setdefault("users", []).append(user)
    return user


def build_initial_state(
    *,
    server: str,
    private_key: str,
    public_key: str,
    short_id: str,
    client_name: str,
    client_uuid: str | None = None,
) -> dict[str, Any]:
    state: dict[str, Any] = {
        "created_at": now_iso(),
        "server": validate_server(server),
        "port": DEFAULT_PORT,
        "sni": DEFAULT_SNI,
        "dest": DEFAULT_DEST,
        "fingerprint": DEFAULT_FINGERPRINT,
        "flow": DEFAULT_FLOW,
        "private_key": private_key,
        "public_key": public_key,
        "short_id": short_id,
        "users": [],
    }
    add_state_user(state, client_name, client_uuid)
    return state


def build_vless_link(state: dict[str, Any], user: dict[str, str]) -> str:
    params = {
        "security": "reality",
        "encryption": "none",
        "pbk": state["public_key"],
        "fp": state.get("fingerprint", DEFAULT_FINGERPRINT),
        "sni": state.get("sni", DEFAULT_SNI),
        "sid": state["short_id"],
        "type": "tcp",
        "flow": state.get("flow", DEFAULT_FLOW),
    }
    query = urllib.parse.urlencode(params, safe="")
    tag = urllib.parse.quote(f"Reality-WARP-{user['name']}", safe="")
    return f"vless://{user['uuid']}@{state['server']}:{state.get('port', DEFAULT_PORT)}?{query}#{tag}"


def build_xray_config(state: dict[str, Any]) -> dict[str, Any]:
    clients = [
        {"id": user["uuid"], "flow": state.get("flow", DEFAULT_FLOW)}
        for user in state.get("users", [])
    ]
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "listen": "0.0.0.0",
                "port": state.get("port", DEFAULT_PORT),
                "protocol": "vless",
                "settings": {"clients": clients, "decryption": "none"},
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "show": False,
                        "dest": state.get("dest", DEFAULT_DEST),
                        "xver": 0,
                        "serverNames": [state.get("sni", DEFAULT_SNI)],
                        "privateKey": state["private_key"],
                        "shortIds": [state["short_id"]],
                    },
                },
            }
        ],
        "outbounds": [
            {
                "tag": "warp",
                "protocol": "freedom",
                "settings": {},
                "streamSettings": {"sockopt": {"interface": "wgcf"}},
            },
            {"tag": "direct", "protocol": "freedom"},
        ],
        "routing": {
            "rules": [
                {
                    "type": "field",
                    "network": "tcp,udp",
                    "outboundTag": "warp",
                }
            ]
        },
    }


def normalize_wgcf_profile(text: str) -> str:
    lines: list[str] = []
    saw_allowed = False
    for line in text.splitlines():
        stripped = line.strip()
        key = stripped.split("=", 1)[0].strip().lower() if "=" in stripped else ""
        if key == "dns":
            continue
        if key == "allowedips":
            if not saw_allowed:
                prefix = line[: len(line) - len(line.lstrip())]
                lines.append(f"{prefix}AllowedIPs = {DEFAULT_WARP_ALLOWED_IPS}")
                saw_allowed = True
            continue
        lines.append(line)
    if not saw_allowed:
        lines.append(f"AllowedIPs = {DEFAULT_WARP_ALLOWED_IPS}")
    return "\n".join(lines).rstrip() + "\n"


def build_wgcf_service() -> str:
    return f"""[Unit]
Description=Manual WARP wgcf interface for Xray
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=-/usr/sbin/ip link delete wgcf
ExecStart=/usr/sbin/ip link add wgcf type wireguard
ExecStart=/usr/bin/wg setconf wgcf {WGCF_STRIPPED_PATH}
ExecStart=/usr/sbin/ip addr add {DEFAULT_WARP_ADDRESS} dev wgcf
ExecStart=/usr/sbin/ip link set up dev wgcf
ExecStop=-/usr/sbin/ip link delete wgcf

[Install]
WantedBy=multi-user.target
"""


def backup_file(path: Path) -> Path | None:
    if not path.exists():
        return None
    backup = path.with_name(f"{path.name}.bak.{int(time.time())}")
    shutil.copy2(path, backup)
    return backup


def write_json(path: Path, data: dict[str, Any], mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.chmod(tmp, mode)
    tmp.replace(path)


def write_xray_config_with_validation(
    state: dict[str, Any],
    *,
    runner: Runner,
    path: Path = XRAY_CONFIG_PATH,
) -> None:
    backup = backup_file(path)
    write_json(path, build_xray_config(state))
    try:
        runner.run(["xray", "run", "-test", "-config", str(path)])
    except Exception:
        if backup is not None:
            shutil.copy2(backup, path)
        else:
            path.unlink(missing_ok=True)
        raise


def install_packages(runner: Runner) -> None:
    runner.run(["apt", "update"])
    runner.run(["apt", "upgrade", "-y"])
    runner.run(
        [
            "apt",
            "install",
            "curl",
            "wget",
            "unzip",
            "nano",
            "wireguard-tools",
            "jq",
            "openssl",
            "-y",
        ]
    )


def install_xray(runner: Runner) -> None:
    script = urllib.request.urlopen(
        "https://github.com/XTLS/Xray-install/raw/main/install-release.sh",
        timeout=60,
    ).read()
    runner.run(["bash", "-c", script.decode("utf-8"), "@", "install"])
    runner.run(["xray", "version"])


def install_wgcf(runner: Runner) -> None:
    data = urllib.request.urlopen(WGCF_URL, timeout=120).read()
    tmp = Path("/tmp") / WGCF_ASSET
    tmp.write_bytes(data)
    os.chmod(tmp, 0o755)
    shutil.move(str(tmp), WGCF_BIN_PATH)
    os.chmod(WGCF_BIN_PATH, 0o755)
    runner.run([str(WGCF_BIN_PATH), "--version"])


def generate_reality_keys(runner: Runner) -> tuple[str, str]:
    result = runner.run(["xray", "x25519"])
    private_key = ""
    public_key = ""
    for line in result.stdout.splitlines():
        if line.lower().startswith("private key:"):
            private_key = line.split(":", 1)[1].strip()
        if line.lower().startswith("public key:"):
            public_key = line.split(":", 1)[1].strip()
    if not private_key or not public_key:
        raise XrayWarpError("Could not parse xray x25519 output.")
    return private_key, public_key


def setup_wgcf(runner: Runner, workdir: Path = STATE_DIR) -> None:
    workdir.mkdir(parents=True, exist_ok=True)
    account = workdir / "wgcf-account.toml"
    profile = workdir / "wgcf-profile.conf"
    if not account.exists():
        runner.run([str(WGCF_BIN_PATH), "register", "--accept-tos"], cwd=workdir)
    if not profile.exists():
        runner.run([str(WGCF_BIN_PATH), "generate"], cwd=workdir)
    normalized = normalize_wgcf_profile(profile.read_text(encoding="utf-8"))
    profile.write_text(normalized, encoding="utf-8")
    os.chmod(profile, 0o600)
    stripped = runner.run(["wg-quick", "strip", str(profile)]).stdout
    WIREGUARD_DIR.mkdir(parents=True, exist_ok=True)
    WGCF_STRIPPED_PATH.write_text(stripped, encoding="utf-8")
    os.chmod(WGCF_STRIPPED_PATH, 0o600)
    WGCF_SERVICE_PATH.write_text(build_wgcf_service(), encoding="utf-8")
    os.chmod(WGCF_SERVICE_PATH, 0o644)
    runner.run(["systemctl", "daemon-reload"])
    runner.run(["systemctl", "enable", "--now", WGCF_SERVICE_PATH.name])


def restart_xray(runner: Runner) -> None:
    runner.run(["systemctl", "restart", "xray"])
    runner.run(["systemctl", "enable", "xray"])


def is_local_tcp_port_open(port: int, host: str = "127.0.0.1", timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def local_port_warning(state: dict[str, Any]) -> str | None:
    port = int(state.get("port", DEFAULT_PORT))
    if is_local_tcp_port_open(port):
        return None
    return f"warning: Xray is not listening on 127.0.0.1:{port}"


def run_install(server: str, client_name: str, runner: Runner) -> str:
    require_root()
    validate_name(client_name)
    server = validate_server(server)
    install_packages(runner)
    install_xray(runner)
    install_wgcf(runner)
    private_key, public_key = generate_reality_keys(runner)
    state = build_initial_state(
        server=server,
        private_key=private_key,
        public_key=public_key,
        short_id=new_short_id(),
        client_name=client_name,
    )
    setup_wgcf(runner)
    write_xray_config_with_validation(state, runner=runner)
    save_state(state)
    restart_xray(runner)
    return build_vless_link(state, user_by_name(state, client_name))


def run_add_user(name: str, runner: Runner) -> str:
    require_root()
    state = load_state()
    user = add_state_user(state, name)
    write_xray_config_with_validation(state, runner=runner)
    save_state(state)
    restart_xray(runner)
    return build_vless_link(state, user)


def status_report(runner: Runner) -> dict[str, Any]:
    report: dict[str, Any] = {}
    for key, args in {
        "xray": ["systemctl", "is-active", "xray"],
        "wgcf_service": ["systemctl", "is-active", WGCF_SERVICE_PATH.name],
        "wgcf_link": ["ip", "link", "show", "wgcf"],
        "wireguard": ["wg", "show", "wgcf"],
    }.items():
        result = runner.run(args, check=False)
        report[key] = {
            "ok": result.returncode == 0,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
        }
    try:
        state = load_state()
        port = int(state.get("port", DEFAULT_PORT))
        report["xray_local_port"] = {
            "ok": is_local_tcp_port_open(port),
            "host": "127.0.0.1",
            "port": port,
        }
    except XrayWarpError as exc:
        report["xray_local_port"] = {"ok": False, "error": str(exc)}
    return report
