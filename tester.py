import copy
from dataclasses import dataclass, field
import logging
import os
import socket
import subprocess
import time
from typing import Callable, Optional

from fake_tcp import BypassConfig
from engine import ProxyEngine

logger = logging.getLogger("BenchmarkTester")


@dataclass
class PresetConfig:
    id: int
    name: str
    offset_label: str
    http_label: str
    rst_label: str
    driver_label: str
    options: dict = field(default_factory=dict)


def check_target_ip_alive(target_ip: str, target_port: int = 443, timeout: float = 2.0) -> tuple[bool, str]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        t0 = time.time()
        s.connect((target_ip, target_port))
        dt = int((time.time() - t0) * 1000)
        s.close()
        return True, f"OK ({dt}ms)"
    except Exception as e:
        return False, str(e)


def check_socks_connectivity(socks_addr: str) -> tuple[bool, str]:
    try:
        if ":" not in socks_addr:
            return False, "فرمت آدرس نامعتبر است (باید host:port باشد)"
        host, port_str = socks_addr.split(":", 1)
        port = int(port_str)
        s = socket.create_connection((host, port), timeout=1.5)
        s.close()
        return True, "OK"
    except Exception as e:
        return False, f"عدم امکان اتصال به پورت ساکس ({e})"


def generate_strategy_presets(fake_sni: str = "hcaptcha.com") -> list[PresetConfig]:
    presets = []
    p_id = 1

    # Clean list of Sequence Offsets
    offset_defs = [
        ("classic", -1, "Classic (-len)"),
        ("offset", -1, "Seq -1"),
        ("offset", -2, "Seq -2"),
        ("offset", -3, "Seq -3"),
        ("offset", -5, "Seq -5"),
        ("offset", -7, "Seq -7"),
        ("offset", -10, "Seq -10"),
        ("offset", -20, "Seq -20"),
        ("offset", -30, "Seq -30"),
        ("offset", -50, "Seq -50"),
        ("offset", -70, "Seq -70"),
        ("offset", -100, "Seq -100"),
        ("offset", -200, "Seq -200"),
        ("offset", -300, "Seq -300"),
        ("offset", -500, "Seq -500"),
        ("offset", -700, "Seq -700"),
        ("offset", -1000, "Seq -1K"),
        ("offset", -2000, "Seq -2K"),
        ("offset", -3000, "Seq -3K"),
        ("offset", -5000, "Seq -5K"),
        ("offset", -10000, "Seq -10K"),
        ("offset", -20000, "Seq -20K"),
        ("offset", -50000, "Seq -50K"),
        ("offset", 1, "Seq +1"),
        ("offset", 100, "Seq +100"),
        ("offset", 1000, "Seq +1K"),
        ("abs", 0, "Seq = 0"),
        ("abs", 2147483648, "Seq = Mid (0x8000)"),
    ]

    http_modes = [
        ("none", "None"),
        ("get", "HTTP GET"),
        ("head", "HTTP HEAD"),
    ]

    rst_modes = [
        (False, "No RST"),
        (True, "Fake RST"),
    ]

    # Combine Sequence x Fake HTTP x Fake RST (Npcap Direct)
    for o_type, o_val, o_name in offset_defs:
        for h_mode, h_label in http_modes:
            for rst_val, rst_label in rst_modes:
                name = f"{o_name} | {h_label} | {rst_label} | Npcap"
                opts = {
                    "wrong_seq": True,
                    "seq_offset_type": o_type,
                    "seq_offset_val": o_val,
                    "fake_http": h_mode,
                    "fake_rst": rst_val,
                    "use_npcap": True,
                    "fake_sni": fake_sni,
                }
                presets.append(PresetConfig(p_id, name, o_name, h_label, rst_label, "Npcap", opts))
                p_id += 1

    # WinDivert native driver comparison for top offsets
    for o_type, o_val, o_name in offset_defs[:15]:
        for h_mode, h_label in [("none", "None"), ("get", "HTTP GET")]:
            name = f"{o_name} | {h_label} | WinDivert"
            opts = {
                "wrong_seq": True,
                "seq_offset_type": o_type,
                "seq_offset_val": o_val,
                "fake_http": h_mode,
                "fake_rst": False,
                "use_npcap": False,
                "fake_sni": fake_sni,
            }
            presets.append(PresetConfig(p_id, name, o_name, h_label, "No RST", "WinDivert", opts))
            p_id += 1

    return presets


def build_bypass_config_from_opts(opts: dict, fallback_sni: str = "hcaptcha.com") -> BypassConfig:
    return BypassConfig(
        wrong_seq=opts.get("wrong_seq", True),
        seq_offset_type=opts.get("seq_offset_type", "classic"),
        seq_offset_val=int(opts.get("seq_offset_val", -1)),
        fake_http=opts.get("fake_http", "none"),
        fake_rst=opts.get("fake_rst", False),
        use_npcap=opts.get("use_npcap", True),
        fake_sni=opts.get("fake_sni", fallback_sni),
    )


def test_preset_with_live_engine(
    engine: ProxyEngine,
    preset: PresetConfig,
    socks_addr: str = "127.0.0.1:10808",
    test_type: str = "quick",  # 'quick', 'ping', 'speed'
    repeats: int = 4,
    timeout_per_probe: int = 7
) -> dict:
    new_cfg = build_bypass_config_from_opts(preset.options, fallback_sni=engine.fake_sni)
    engine.bypass_config = new_cfg
    time.sleep(0.06)

    socks_url = f"socks5h://{socks_addr}"
    probe_url = "https://www.google.com"
    no_window_flag = 0x08000000  # CREATE_NO_WINDOW on Windows

    # --- QUICK TEST (1 PROBE) ---
    if test_type == "quick":
        t0 = time.time()
        try:
            res = subprocess.run(
                [
                    "curl.exe", "-s", "-k", "-L", "-o", "NUL",
                    "-w", "%{http_code}",
                    "-m", str(timeout_per_probe),
                    "-x", socks_url,
                    probe_url
                ],
                capture_output=True, text=True, timeout=timeout_per_probe + 1,
                creationflags=no_window_flag
            )
            dt = int((time.time() - t0) * 1000)
            code = res.stdout.strip()
            if code in ("200", "301", "302", "204") or (code.isdigit() and 200 <= int(code) < 400):
                return {
                    "id": preset.id,
                    "name": preset.name,
                    "offset": preset.offset_label,
                    "http": preset.http_label,
                    "rst": preset.rst_label,
                    "driver": preset.driver_label,
                    "ping": f"{dt} ms",
                    "ping_num": dt,
                    "speed": "-",
                    "speed_num": 0.0,
                    "status": "متصل",
                    "success": True,
                    "ratio": "1/1",
                    "options": preset.options,
                }
            else:
                return {
                    "id": preset.id,
                    "name": preset.name,
                    "offset": preset.offset_label,
                    "http": preset.http_label,
                    "rst": preset.rst_label,
                    "driver": preset.driver_label,
                    "ping": "Timeout",
                    "ping_num": 999999,
                    "speed": "-",
                    "speed_num": 0.0,
                    "status": "قطع",
                    "success": False,
                    "ratio": "0/1",
                    "options": preset.options,
                }
        except Exception:
            return {
                "id": preset.id,
                "name": preset.name,
                "offset": preset.offset_label,
                "http": preset.http_label,
                "rst": preset.rst_label,
                "driver": preset.driver_label,
                "ping": "Timeout",
                "ping_num": 999999,
                "speed": "-",
                "speed_num": 0.0,
                "status": "قطع",
                "success": False,
                "ratio": "0/1",
                "options": preset.options,
            }

    # --- SPEED TEST (4 PROBES) ---
    elif test_type == "speed":
        speeds = []
        latencies = []
        success = 0
        for probe_idx in range(repeats):
            t0 = time.time()
            try:
                res = subprocess.run(
                    [
                        "curl.exe", "-s", "-k", "-L", "-o", "NUL",
                        "-w", "%{http_code} %{speed_download}",
                        "-m", str(timeout_per_probe),
                        "-x", socks_url,
                        probe_url
                    ],
                    capture_output=True, text=True, timeout=timeout_per_probe + 1,
                    creationflags=no_window_flag
                )
                dt = int((time.time() - t0) * 1000)
                parts = res.stdout.strip().split()
                code = parts[0] if parts else "000"
                speed = float(parts[1]) if len(parts) > 1 else 0.0
                if (code in ("200", "301", "302", "204") or (code.isdigit() and 200 <= int(code) < 400)) or speed > 0:
                    speeds.append(speed)
                    latencies.append(dt)
                    success += 1
                elif probe_idx == 0:
                    break
            except Exception:
                if probe_idx == 0:
                    break

        if success > 0:
            avg_speed_kb = (sum(speeds) / len(speeds)) / 1024.0
            avg_ping = int(sum(latencies) / len(latencies))
            speed_str = f"{avg_speed_kb:.1f} KB/s" if avg_speed_kb < 1024 else f"{(avg_speed_kb/1024.0):.2f} MB/s"
            status = "موفق" if success == repeats else f"ناپایدار ({success}/{repeats})"
            return {
                "id": preset.id,
                "name": preset.name,
                "offset": preset.offset_label,
                "http": preset.http_label,
                "rst": preset.rst_label,
                "driver": preset.driver_label,
                "ping": f"{avg_ping} ms ({success}/{repeats})",
                "ping_num": avg_ping,
                "speed": speed_str,
                "speed_num": avg_speed_kb,
                "status": status,
                "success": True,
                "ratio": f"{success}/{repeats}",
                "options": preset.options,
            }
        else:
            return {
                "id": preset.id,
                "name": preset.name,
                "offset": preset.offset_label,
                "http": preset.http_label,
                "rst": preset.rst_label,
                "driver": preset.driver_label,
                "ping": f"Timeout (0/{repeats})",
                "ping_num": 999999,
                "speed": "0 KB/s",
                "speed_num": 0.0,
                "status": "ناموفق",
                "success": False,
                "ratio": f"0/{repeats}",
                "options": preset.options,
            }

    # --- PING TEST (4 PROBES) ---
    else:
        latencies = []
        success = 0
        for probe_idx in range(repeats):
            t0 = time.time()
            try:
                res = subprocess.run(
                    [
                        "curl.exe", "-s", "-k", "-L", "-o", "NUL",
                        "-w", "%{http_code}",
                        "-m", str(timeout_per_probe),
                        "-x", socks_url,
                        probe_url
                    ],
                    capture_output=True, text=True, timeout=timeout_per_probe + 1,
                    creationflags=no_window_flag
                )
                dt = int((time.time() - t0) * 1000)
                code = res.stdout.strip()
                if code in ("200", "301", "302", "204") or (code.isdigit() and 200 <= int(code) < 400):
                    latencies.append(dt)
                    success += 1
                elif probe_idx == 0:
                    break
            except Exception:
                if probe_idx == 0:
                    break

        if success > 0:
            avg_ping = int(sum(latencies) / len(latencies))
            status = "موفق" if success == repeats else f"ناپایدار ({success}/{repeats})"
            return {
                "id": preset.id,
                "name": preset.name,
                "offset": preset.offset_label,
                "http": preset.http_label,
                "rst": preset.rst_label,
                "driver": preset.driver_label,
                "ping": f"{avg_ping} ms ({success}/{repeats})",
                "ping_num": avg_ping,
                "speed": "-",
                "speed_num": 0.0,
                "status": status,
                "success": True,
                "ratio": f"{success}/{repeats}",
                "options": preset.options,
            }
        else:
            return {
                "id": preset.id,
                "name": preset.name,
                "offset": preset.offset_label,
                "http": preset.http_label,
                "rst": preset.rst_label,
                "driver": preset.driver_label,
                "ping": f"Timeout (0/{repeats})",
                "ping_num": 999999,
                "speed": "-",
                "speed_num": 0.0,
                "status": "ناموفق",
                "success": False,
                "ratio": f"0/{repeats}",
                "options": preset.options,
            }


# --- IP x SNI ORIGINAL METHOD TESTER ---
def read_lines_from_file(file_path: str) -> list[str]:
    if not os.path.exists(file_path):
        return []
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    return lines
