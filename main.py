import argparse
import ctypes
import logging
import os
import signal
import subprocess
import sys
import time

from engine import ProxyEngine, load_config_file


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def restart_as_admin():
    try:
        project_dir = os.path.dirname(os.path.abspath(__file__))
        script = os.path.join(project_dir, "main.py")
        params = " ".join([f'"{arg}"' for arg in sys.argv[1:] if arg != "--no-elevate"])
        ret = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            f'"{script}" {params}',
            project_dir,
            1
        )
        if ret > 32:
            sys.exit(0)
    except Exception as e:
        print(f"Failed to elevate to administrator: {e}")


def ensure_system_permissions():
    """Ensure working directory and network driver service readiness."""
    project_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(project_dir)

    # Start Npcap service if not running
    try:
        subprocess.run(["sc.exe", "start", "npcap"], capture_output=True, timeout=2, creationflags=0x08000000)
    except Exception:
        pass


def run_cli():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S"
    )

    print("=" * 60)
    print("  SNI Spoofing & TCP DPI Bypass Proxy (CLI Mode)")
    print("  Compatible with v2rayN (vless + ws + tls)")
    print("=" * 60)

    config = load_config_file()
    engine = ProxyEngine(config, log_callback=lambda m: print(f"[CLI] {m}"))

    def sig_handler(sig, frame):
        print("\n[!] Shutting down gracefully...")
        engine.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    try:
        engine.start()
        print("[*] Press Ctrl+C to stop.")
        while engine.is_running:
            time.sleep(1)
    except PermissionError:
        print("\n[ERROR] WinDivert requires Administrator privileges. Please run as Administrator!")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Service failed to start: {e}")
        engine.stop()
        sys.exit(1)


def main():
    ensure_system_permissions()

    parser = argparse.ArgumentParser(description="SNI Spoofing & DPI Bypass")
    parser.add_argument("--cli", action="store_true", help="Run in headless CLI mode instead of GUI")
    parser.add_argument("--no-elevate", action="store_true", help="Do not attempt auto-elevation")
    args = parser.parse_args()

    if args.cli:
        run_cli()
    else:
        try:
            from gui import run_gui
            run_gui()
        except ImportError as e:
            print(f"Failed to load GUI: {e}. Falling back to CLI mode.")
            run_cli()


if __name__ == "__main__":
    if not is_admin() and "--no-elevate" not in sys.argv and "-h" not in sys.argv and "--help" not in sys.argv:
        restart_as_admin()
    main()
