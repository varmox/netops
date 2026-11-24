"""MikroTik RouterOS over SSH: `/export` as text, optionally a binary `/system backup`.

The text export is read from stdout, so it writes nothing on the router. The binary backup has to be
saved on the router first; it is downloaded over SFTP and deleted again.
"""
import re
import time

import asyncssh

from .. import vault

# RouterOS 7.16 could only verify RSA signatures; RSA keys work on every version.
_ALGS = ["rsa-sha2-256", "rsa-sha2-512", "ssh-rsa"]


def _strip_header(export: str) -> str:
    # First line is "# 2026-11-23 15:36:56 by RouterOS 7.25.2": it changes on every export.
    return re.sub(r"^# \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} by RouterOS.*\n", "", export, count=1)


async def collect(device, cfg: dict) -> list[tuple[str, bytes, str | None]]:
    key = asyncssh.import_private_key(vault.secret_or_file(cfg, "key_vault", "key"))
    async with asyncssh.connect(
        device.host, port=int(cfg.get("port", 22)), username=cfg["user"], client_keys=[key],
        known_hosts=None, server_host_key_algs=_ALGS, signature_algs=_ALGS, connect_timeout=15,
    ) as conn:
        args = " show-sensitive" if cfg.get("show_sensitive") else ""
        r = await conn.run("/export" + args, check=True, timeout=120)
        export = r.stdout.replace("\r\n", "\n")
        files = [("rsc", export.encode(), _strip_header(export))]

        if cfg.get("binary"):
            name = "netops-%d" % int(time.time())
            await conn.run("/system backup save name=%s dont-encrypt=yes" % name, check=True, timeout=120)
            try:
                async with conn.start_sftp_client() as sftp:
                    async with sftp.open(name + ".backup", "rb") as f:
                        data = await f.read()
            finally:
                await conn.run('/file remove [find where name="%s.backup"]' % name, timeout=30)
            files.append(("backup", data, None))
        return files
