import asyncio
import json
import logging
import os
import socket
import sys
import threading
from typing import Callable, Optional

from fake_tcp import BypassConfig, FakeInjectiveConnection, FakeTcpInjector
from utils.network_tools import get_default_interface_ipv4
from utils.packet_templates import ClientHelloMaker

logger = logging.getLogger("ProxyEngine")


def get_base_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def load_config_file(config_path: Optional[str] = None) -> dict:
    if not config_path:
        config_path = os.path.join(get_base_dir(), "config.json")
    if not os.path.exists(config_path):
        default_cfg = {
            "LISTEN_HOST": "0.0.0.0",
            "LISTEN_PORT": 40443,
            "CONNECT_IP": "188.114.98.0",
            "CONNECT_PORT": 443,
            "FAKE_SNI": "auth.vercel.com",
            "BYPASS_OPTIONS": {
                "wrong_seq": True,
                "low_ttl": False,
                "fake_ttl": 5,
                "wrong_chksum": False,
                "fake_rst": False,
                "fake_http": False,
                "tls_frag": False,
                "frag_mode": "sni",
                "fake_ech": False,
                "tcp_overlap": False,
                "tcp_md5": False,
            },
        }
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(default_cfg, f, indent=2)
        return default_cfg

    with open(config_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Ensure BYPASS_OPTIONS exists
    if "BYPASS_OPTIONS" not in data:
        data["BYPASS_OPTIONS"] = {
            "wrong_seq": True,
            "low_ttl": False,
            "fake_ttl": 5,
            "wrong_chksum": False,
            "fake_rst": False,
            "fake_http": False,
            "tls_frag": False,
            "frag_mode": "sni",
            "fake_ech": False,
            "tcp_overlap": False,
            "tcp_md5": False,
        }
    return data


def save_config_file(config_data: dict, config_path: Optional[str] = None):
    if not config_path:
        config_path = os.path.join(get_base_dir(), "config.json")
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config_data, f, indent=2)


class ProxyEngine:
    def __init__(self, config: dict, log_callback: Optional[Callable[[str], None]] = None):
        self.config = config
        self.log_callback = log_callback
        self.is_running = False

        self.listen_host = config.get("LISTEN_HOST", "0.0.0.0")
        self.listen_port = int(config.get("LISTEN_PORT", 40443))
        self.connect_ip = config.get("CONNECT_IP", "188.114.98.0")
        self.connect_port = int(config.get("CONNECT_PORT", 443))
        self.fake_sni = config.get("FAKE_SNI", "auth.vercel.com")

        opts = config.get("BYPASS_OPTIONS", {})
        self.bypass_config = BypassConfig(
            wrong_seq=opts.get("wrong_seq", True),
            low_ttl=opts.get("low_ttl", False),
            fake_ttl=int(opts.get("fake_ttl", 5)),
            wrong_chksum=opts.get("wrong_chksum", False),
            fake_rst=opts.get("fake_rst", False),
            fake_http=opts.get("fake_http", False),
            tls_frag=opts.get("tls_frag", False),
            frag_mode=opts.get("frag_mode", "sni"),
            fake_ech=opts.get("fake_ech", False),
            tcp_overlap=opts.get("tcp_overlap", False),
            tcp_md5=opts.get("tcp_md5", False),
            use_npcap=opts.get("use_npcap", False),
            fake_sni=self.fake_sni,
        )

        self.fake_injective_connections: dict[tuple, FakeInjectiveConnection] = {}
        self.fake_tcp_injector: Optional[FakeTcpInjector] = None
        self.npcap_sender = None
        self.injector_thread: Optional[threading.Thread] = None
        self.loop_thread: Optional[threading.Thread] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.mother_sock: Optional[socket.socket] = None
        self.interface_ipv4: str = ""

    def log(self, message: str):
        logger.info(message)
        if self.log_callback:
            try:
                self.log_callback(message)
            except Exception:
                pass

    async def _relay_loop(self, sock_1: socket.socket, sock_2: socket.socket,
                          peer_task: asyncio.Task, is_client_to_server: bool):
        try:
            loop = asyncio.get_running_loop()
            first = True
            while self.is_running:
                try:
                    data = await loop.sock_recv(sock_1, 65575)
                    if not data:
                        break

                    # Handle TLS Fragmentation if enabled on the first client packet
                    if first and is_client_to_server and self.bypass_config.tls_frag:
                        if ClientHelloMaker.is_tls_client_hello(data):
                            frags = ClientHelloMaker.split_for_sni_fragmentation(
                                data, self.bypass_config.frag_mode
                            )
                            if len(frags) > 1:
                                self.log(f"[FRAG] Splitting ClientHello into {len(frags)} segments ({self.bypass_config.frag_mode})")
                                for frag in frags:
                                    await loop.sock_sendall(sock_2, frag)
                                    await asyncio.sleep(0.002)
                                first = False
                                continue

                    await loop.sock_sendall(sock_2, data)
                    first = False
                except Exception:
                    break
        finally:
            try:
                sock_1.close()
            except Exception:
                pass
            try:
                sock_2.close()
            except Exception:
                pass
            if not peer_task.done():
                peer_task.cancel()

    async def _handle_connection(self, incoming_sock: socket.socket, client_addr):
        conn_id = None
        fake_injective_conn = None
        outgoing_sock = None
        loop = asyncio.get_running_loop()

        try:
            self.log(f"[+] New connection from {client_addr[0]}:{client_addr[1]}")

            # Generate fake payload
            if self.bypass_config.fake_ech:
                fake_data = ClientHelloMaker.get_client_hello_with_ech(
                    os.urandom(32), os.urandom(32), self.fake_sni.encode(), os.urandom(32)
                )
            else:
                fake_data = ClientHelloMaker.get_client_hello_with(
                    os.urandom(32), os.urandom(32), self.fake_sni.encode(), os.urandom(32)
                )

            outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            outgoing_sock.setblocking(False)
            outgoing_sock.bind((self.interface_ipv4, 0))
            outgoing_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

            src_port = outgoing_sock.getsockname()[1]
            fake_injective_conn = FakeInjectiveConnection(
                outgoing_sock, self.interface_ipv4, self.connect_ip,
                src_port, self.connect_port, fake_data,
                self.bypass_config, incoming_sock
            )
            conn_id = fake_injective_conn.id
            self.fake_injective_connections[conn_id] = fake_injective_conn

            # Connect to destination
            try:
                await loop.sock_connect(outgoing_sock, (self.connect_ip, self.connect_port))
            except Exception as e:
                self.log(f"[-] Connect to {self.connect_ip}:{self.connect_port} failed: {e}")
                return

            # Wait for injection completion
            cfg = self.bypass_config
            if cfg.wrong_seq and not cfg.low_ttl and not cfg.wrong_chksum:
                try:
                    await asyncio.wait_for(fake_injective_conn.t2a_event.wait(), timeout=1.5)
                except asyncio.TimeoutError:
                    pass
            else:
                try:
                    await asyncio.wait_for(fake_injective_conn.t2a_event.wait(), timeout=0.25)
                except asyncio.TimeoutError:
                    pass

            fake_injective_conn.monitor = False
            if conn_id in self.fake_injective_connections:
                del self.fake_injective_connections[conn_id]

            # Start bidirectional relay
            c2s_task = asyncio.current_task()
            s2c_task = asyncio.create_task(
                self._relay_loop(outgoing_sock, incoming_sock, c2s_task, is_client_to_server=False)
            )
            await self._relay_loop(incoming_sock, outgoing_sock, s2c_task, is_client_to_server=True)

        except Exception as e:
            logger.debug("Handle connection error: %s", e)
        finally:
            if conn_id and conn_id in self.fake_injective_connections:
                del self.fake_injective_connections[conn_id]
            if fake_injective_conn:
                fake_injective_conn.monitor = False
            try:
                incoming_sock.close()
            except Exception:
                pass
            if outgoing_sock:
                try:
                    outgoing_sock.close()
                except Exception:
                    pass

    async def _server_main(self):
        self.loop = asyncio.get_running_loop()
        self.mother_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.mother_sock.setblocking(False)
        self.mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.mother_sock.bind((self.listen_host, self.listen_port))
        self.mother_sock.listen(128)

        self.log(f"[*] Proxy server listening on {self.listen_host}:{self.listen_port}")
        self.log(f"[*] Target destination: {self.connect_ip}:{self.connect_port}")
        self.log(f"[*] Fake SNI: {self.fake_sni}")

        # Summary of active strategies
        active = []
        if self.bypass_config.wrong_seq:
            active.append("wrong_seq")
        if self.bypass_config.low_ttl:
            active.append(f"low_ttl(ttl={self.bypass_config.fake_ttl})")
        if self.bypass_config.wrong_chksum:
            active.append("wrong_chksum")
        if self.bypass_config.fake_rst:
            active.append("fake_rst")
        if self.bypass_config.fake_http:
            active.append("fake_http")
        if self.bypass_config.tls_frag:
            active.append(f"tls_frag({self.bypass_config.frag_mode})")
        if self.bypass_config.fake_ech:
            active.append("fake_ech")
        if self.bypass_config.tcp_overlap:
            active.append("tcp_overlap")
        self.log(f"[*] Active bypass strategies: {', '.join(active) if active else 'None'}")

        while self.is_running:
            try:
                client_sock, client_addr = await self.loop.sock_accept(self.mother_sock)
                client_sock.setblocking(False)
                client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                asyncio.create_task(self._handle_connection(client_sock, client_addr))
            except Exception:
                if not self.is_running:
                    break

    def _run_asyncio_thread(self):
        asyncio.run(self._server_main())

    def start(self):
        if self.is_running:
            return

        self.interface_ipv4 = get_default_interface_ipv4(self.connect_ip)
        if not self.interface_ipv4:
            raise RuntimeError(f"Could not determine default interface IPv4 for {self.connect_ip}")

        self.log(f"[*] Detected local IPv4: {self.interface_ipv4}")

        # Initialize Npcap direct NIC injection if requested
        if self.bypass_config.use_npcap:
            try:
                from utils.npcap_tools import find_npcap_dev_by_ip, get_mac_by_arp, NpcapDirectSender
                import scapy.all as scapy
                dev = find_npcap_dev_by_ip(self.interface_ipv4)
                if dev:
                    try:
                        src_mac_str = scapy.get_if_hwaddr(dev["name"])
                        src_mac = bytes.fromhex(src_mac_str.replace(":", "").replace("-", ""))
                    except Exception:
                        src_mac = None

                    # Resolve gateway MAC
                    gw_ip = "192.168.1.1"
                    try:
                        gw_ip = scapy.conf.route.route(self.connect_ip)[2]
                    except Exception:
                        pass
                    gw_mac = get_mac_by_arp(gw_ip, self.interface_ipv4) if gw_ip else None

                    self.npcap_sender = NpcapDirectSender(dev["name"], src_mac, gw_mac)
                    self.log(f"[✓] Npcap Direct NIC injection enabled on: {dev['description']}")
                else:
                    self.log(f"[-] Npcap adapter for {self.interface_ipv4} not found, using WinDivert fallback.")
            except Exception as e:
                self.log(f"[-] Failed to initialize Npcap: {e}, using WinDivert fallback.")

        # Build WinDivert filter
        w_filter = (
            f"tcp and ("
            f"(ip.SrcAddr == {self.interface_ipv4} and ip.DstAddr == {self.connect_ip}) or "
            f"(ip.SrcAddr == {self.connect_ip} and ip.DstAddr == {self.interface_ipv4})"
            f")"
        )

        self.fake_tcp_injector = FakeTcpInjector(
            w_filter, self.fake_injective_connections, self.bypass_config,
            npcap_sender=self.npcap_sender
        )

        self.is_running = True

        # Start injector in separate thread
        self.injector_thread = threading.Thread(
            target=self.fake_tcp_injector.run, daemon=True, name="WinDivertInjector"
        )
        self.injector_thread.start()

        # Start asyncio proxy server in separate thread
        self.loop_thread = threading.Thread(
            target=self._run_asyncio_thread, daemon=True, name="ProxyServer"
        )
        self.loop_thread.start()

        self.log("[✓] Service started successfully.")

    def stop(self):
        if not self.is_running:
            return
        self.log("[*] Stopping service...")
        self.is_running = False

        if self.fake_tcp_injector:
            self.fake_tcp_injector.stop()

        if self.npcap_sender:
            try:
                self.npcap_sender.close()
            except Exception:
                pass
            self.npcap_sender = None

        if self.mother_sock:
            try:
                self.mother_sock.close()
            except Exception:
                pass

        # Close all active connections
        for conn in list(self.fake_injective_connections.values()):
            conn.monitor = False
            try:
                conn.sock.close()
            except Exception:
                pass
            try:
                conn.peer_sock.close()
            except Exception:
                pass
        self.fake_injective_connections.clear()

        self.log("[✓] Service stopped.")
