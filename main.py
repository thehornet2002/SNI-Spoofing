import argparse
import logging
import signal
import sys
import time

from engine import ProxyEngine, load_config_file


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
    parser = argparse.ArgumentParser(description="SNI Spoofing & DPI Bypass")
    parser.add_argument("--cli", action="store_true", help="Run in headless CLI mode instead of GUI")
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
    main()
