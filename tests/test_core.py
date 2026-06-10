import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from xray_warp.core import (
    CommandResult,
    Runner,
    XrayWarpError,
    add_state_user,
    build_initial_state,
    build_vless_link,
    build_xray_config,
    generate_reality_keys,
    install_wgcf,
    install_xray,
    normalize_wgcf_profile,
    save_state,
    load_state,
    write_xray_config_with_validation,
)


class FakeRunner(Runner):
    def __init__(self, fail=False):
        self.fail = fail
        self.calls = []

    def run(self, args, *, cwd=None, check=True, input_text=None):
        self.calls.append(args)
        if self.fail:
            result = CommandResult(args, 1, "", "bad config")
            if check:
                raise XrayWarpError("bad config")
            return result
        return CommandResult(args, 0, "Configuration OK.", "")


class RecordingRunner(Runner):
    def __init__(self):
        self.calls = []

    def run(self, args, *, cwd=None, check=True, input_text=None):
        self.calls.append((args, input_text))
        return CommandResult(args, 0, "ok", "")


class X25519Runner(Runner):
    def __init__(self, stdout="", stderr=""):
        self.stdout = stdout
        self.stderr = stderr

    def run(self, args, *, cwd=None, check=True, input_text=None):
        return CommandResult(args, 0, self.stdout, self.stderr)


def sample_state():
    return build_initial_state(
        server="144.31.188.173",
        private_key="priv",
        public_key="pub",
        short_id="f4c82a91d8e74a3b",
        client_name="main",
        client_uuid="11111111-1111-4111-8111-111111111111",
    )


class CoreTests(unittest.TestCase):
    def test_build_vless_link(self):
        state = sample_state()
        link = build_vless_link(state, state["users"][0])
        self.assertEqual(
            link,
            "vless://11111111-1111-4111-8111-111111111111@144.31.188.173:443"
            "?security=reality&encryption=none&pbk=pub&fp=chrome"
            "&sni=www.microsoft.com&sid=f4c82a91d8e74a3b&type=tcp"
            "&flow=xtls-rprx-vision#Reality-WARP-main",
        )

    def test_normalize_wgcf_profile(self):
        text = """[Interface]
PrivateKey = x
DNS = 1.1.1.1

[Peer]
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = engage.cloudflareclient.com:2408
"""
        normalized = normalize_wgcf_profile(text)
        self.assertNotIn("DNS =", normalized)
        self.assertIn("AllowedIPs = 162.159.192.0/24", normalized)
        self.assertNotIn("0.0.0.0/0", normalized)

    def test_build_xray_config_adds_users(self):
        state = sample_state()
        add_state_user(state, "phone", "22222222-2222-4222-8222-222222222222")
        config = build_xray_config(state)
        clients = config["inbounds"][0]["settings"]["clients"]
        self.assertEqual(len(clients), 2)
        self.assertEqual(clients[0]["flow"], "xtls-rprx-vision")
        sockopt = config["outbounds"][0]["streamSettings"]["sockopt"]
        self.assertEqual(sockopt["interface"], "wgcf")

    def test_state_round_trip(self):
        state = sample_state()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            save_state(state, path)
            loaded = load_state(path)
            self.assertEqual(loaded["server"], "144.31.188.173")
            self.assertEqual(loaded["users"][0]["name"], "main")

    def test_rollback_on_invalid_xray_config(self):
        state = sample_state()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            original = {"old": True}
            path.write_text(json.dumps(original), encoding="utf-8")
            with patch("xray_warp.core.time.time", return_value=123):
                with self.assertRaises(XrayWarpError):
                    write_xray_config_with_validation(
                        state, runner=FakeRunner(fail=True), path=path
                    )
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), original)
            self.assertTrue((Path(tmp) / "config.json.bak.123").exists())

    def test_install_xray_uses_official_bash_c_shape(self):
        runner = RecordingRunner()
        with patch("xray_warp.core.urllib.request.urlopen") as urlopen:
            urlopen.return_value.read.return_value = b"echo installer"
            install_xray(runner)
        self.assertEqual(runner.calls[0][0], ["bash", "-c", "echo installer", "@", "install"])
        self.assertIsNone(runner.calls[0][1])
        self.assertEqual(runner.calls[1][0], ["xray", "version"])

    def test_install_wgcf_checks_help_not_version_flag(self):
        runner = RecordingRunner()
        with tempfile.TemporaryDirectory() as tmp:
            with patch("xray_warp.core.urllib.request.urlopen") as urlopen:
                with patch("xray_warp.core.WGCF_BIN_PATH", Path(tmp) / "wgcf"):
                    urlopen.return_value.read.return_value = b"binary"
                    install_wgcf(runner)
        self.assertEqual(runner.calls[0][0][-1], "--help")

    def test_generate_reality_keys_accepts_compact_and_stderr_output(self):
        runner = X25519Runner(
            stderr="PrivateKey: priv123\nPublicKey: pub456\n",
        )
        self.assertEqual(generate_reality_keys(runner), ("priv123", "pub456"))

    def test_generate_reality_keys_accepts_spaced_stdout_output(self):
        runner = X25519Runner(
            stdout="Private key: priv123\nPublic key: pub456\n",
        )
        self.assertEqual(generate_reality_keys(runner), ("priv123", "pub456"))


if __name__ == "__main__":
    unittest.main()
