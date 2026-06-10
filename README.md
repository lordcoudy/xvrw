# xray-warp

Minimal Python CLI for installing Xray VLESS Reality Vision with WARP
WireGuard egress on Ubuntu 22.04.

The tool intentionally avoids `wg-quick up wgcf-profile` and creates a manual
`wgcf` interface instead, so the VPS default route and SSH access are not
captured by WARP.

## Usage

Run as root on the VPS:

```bash
python3 -m xray_warp.cli install --server 144.31.188.173 --client main
```

Then add users later:

```bash
python3 -m xray_warp.cli add-user --name phone
python3 -m xray_warp.cli list-users
python3 -m xray_warp.cli show-link --name phone
python3 -m xray_warp.cli status
```

Install as a console script if desired:

```bash
python3 -m pip install .
xray-warp install --server 144.31.188.173 --client main
```

## Notes

- The CLI must run as root for installation and service changes.
- Secrets are stored in `/etc/xray-warp/state.json`.
- Existing `/usr/local/etc/xray/config.json` is backed up before changes.
- No VPS passwords are stored by this project.
