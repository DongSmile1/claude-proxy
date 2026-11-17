#!/usr/bin/env python3
"""Non-root, no-explicit-proxy HTTP evidence. Never changes network settings."""

import argparse
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import urllib.parse


def clean_env(source):
    return {
        key: value for key, value in source.items()
        if not key.lower().endswith("_proxy")
        and key.upper() not in {"SSLKEYLOGFILE", "CURL_SSL_BACKEND"}
    }


def public_url(value):
    try:
        parts = urllib.parse.urlsplit(value)
        _ = parts.port
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Invalid URL") from exc
    if (parts.scheme not in {"http", "https"} or not parts.hostname
            or parts.username is not None or parts.password is not None
            or parts.query or parts.fragment or any(ord(c) < 33 for c in value)):
        raise argparse.ArgumentTypeError(
            "Use an HTTP(S) endpoint without credentials, query, fragment, or whitespace"
        )
    return value


def extract_ip(body):
    """Do not copy arbitrary website text into a diagnostic report."""
    try:
        value = body.decode("utf-8").strip()
    except UnicodeDecodeError:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    try:
        parsed = json.loads(value)
    except (ValueError, TypeError):
        return None
    if not isinstance(parsed, dict):
        return None
    for field in ("ip", "origin", "query"):
        candidate = parsed.get(field)
        if isinstance(candidate, str):
            try:
                return str(ipaddress.ip_address(candidate.strip()))
            except ValueError:
                pass
    return None


def probe(url, curl, timeout, family):
    start = dt.datetime.now(dt.timezone.utc).isoformat()
    result = {"url": url, "started_utc": start, "curl_exit": None,
              "http_status": None, "remote_ip": None, "reported_ip": None,
              "seconds": None, "response_limit_reached": False, "error": None}
    with tempfile.TemporaryDirectory(prefix="proxy-probe-") as temporary:
        body_path = Path(temporary) / "body"
        command = [curl, "-q", "--silent", "--show-error", "--noproxy", "*",
                   "--proto", "=http,https", "--connect-timeout", str(min(8, timeout)),
                   "--max-time", str(timeout), "--max-filesize", "65536",
                   "--output", str(body_path), "--write-out",
                   "%{http_code}\t%{remote_ip}\t%{time_total}"]
        if family != "auto":
            command.append("--ipv4" if family == "4" else "--ipv6")
        command.extend(["--url", url])
        try:
            completed = subprocess.run(command, capture_output=True, text=True,
                                       env=clean_env(os.environ), timeout=timeout + 3)
        except subprocess.TimeoutExpired:
            result["error"] = "probe_process_timeout"
            return result
        except OSError as exc:
            result["error"] = type(exc).__name__
            return result
        result["curl_exit"] = completed.returncode
        result["response_limit_reached"] = completed.returncode == 63
        fields = completed.stdout.strip().split("\t")
        if len(fields) == 3:
            try:
                result["http_status"] = int(fields[0])
                result["seconds"] = float(fields[2])
            except ValueError:
                result["error"] = "unexpected_curl_metrics"
            try:
                result["remote_ip"] = str(ipaddress.ip_address(fields[1]))
            except ValueError:
                pass
        if completed.returncode:
            result["error"] = (completed.stderr.strip() or "curl_failed")[:600]
        if body_path.exists() and body_path.stat().st_size <= 65536:
            result["reported_ip"] = extract_ip(body_path.read_bytes())
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", action="append", required=True, type=public_url)
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--family", choices=("auto", "4", "6"), default="auto")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not hasattr(os, "geteuid") or os.geteuid() == 0:
        parser.error("Run as an ordinary verified POSIX user, never as root")
    if not 1 <= args.timeout <= 60:
        parser.error("timeout must be between 1 and 60 seconds per URL")
    curl = "/usr/bin/curl" if Path("/usr/bin/curl").is_file() else shutil.which("curl")
    if not curl:
        parser.error("curl is not installed")
    report = {
        "schema": 1, "uid": os.geteuid(), "explicit_proxy": False,
        "curl_config_ignored": True, "redirects_followed": False,
        "family": args.family,
        "meaning": "HTTP probe evidence only; no route or firewall verdict",
        "results": [probe(url, curl, args.timeout, args.family) for url in args.url],
    }
    encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        # Never overwrite a previous run or follow a user-supplied output symlink.
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(encoded)
        print(str(args.output.resolve()))
    else:
        sys.stdout.write(encoded)
    return 0


if __name__ == "__main__":
    sys.exit(main())
