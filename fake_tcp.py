import asyncio
from dataclasses import dataclass
import logging
import socket
import sys
import threading
import time

try:
    from pydivert import Packet
except ImportError:
    Packet = None

from monitor_connection import MonitorConnection
from injecter import TcpInjector
from utils.packet_templates import HttpProbeMaker

logger = logging.getLogger("FakeTcp")


@dataclass
class BypassConfig:
    wrong_seq: bool = True
    seq_offset_type: str = "classic"  # 'classic', 'offset', 'abs'
    seq_offset_val: int = -1
    fake_http: str = "none"  # 'none', 'get', 'head'
    fake_rst: bool = False
    fake_sni: str = "hcaptcha.com"
    use_npcap: bool = True


class FakeInjectiveConnection(MonitorConnection):
    def __init__(self, sock: socket.socket, src_ip: str, dst_ip: str,
                 src_port: int, dst_port: int, fake_data: bytes,
                 bypass_config: BypassConfig, peer_sock: socket.socket):
        super().__init__(sock, src_ip, dst_ip, src_port, dst_port)
        self.fake_data = fake_data
        self.bypass_config = bypass_config
        self.sch_fake_sent = False
        self.fake_sent = False
        self.t2a_event = asyncio.Event()
        self.t2a_msg = ""
        self.peer_sock = peer_sock
        self.running_loop = asyncio.get_running_loop()


class FakeTcpInjector(TcpInjector):
    def __init__(self, w_filter: str, connections: dict[tuple, FakeInjectiveConnection],
                 bypass_config: BypassConfig, npcap_sender=None):
        super().__init__(w_filter)
        self.connections = connections
        self.bypass_config = bypass_config
        self.npcap_sender = npcap_sender

    def _send_fake_packet(self, packet: Packet, recalculate_checksum: bool = True):
        if self.bypass_config.use_npcap and self.npcap_sender:
            if recalculate_checksum:
                packet.recalculate_checksums()
            self.npcap_sender.send_ip_packet(packet.raw)
        else:
            self.w.send(packet, recalculate_checksum)

    def _send_fake_http(self, base_packet: Packet, connection: FakeInjectiveConnection, method: str = "get"):
        try:
            if method == "head":
                http_payload = f"HEAD / HTTP/1.1\r\nHost: {self.bypass_config.fake_sni}\r\nUser-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n".encode()
            else:
                http_payload = HttpProbeMaker.get_fake_get(self.bypass_config.fake_sni)

            pkt = base_packet
            pkt.tcp.psh = True
            pkt.tcp.ack = True
            pkt.tcp.syn = False
            pkt.tcp.rst = False
            pkt.tcp.fin = False
            pkt.tcp.payload = http_payload
            pkt.ip.packet_len = pkt.ip.header_len + pkt.tcp.header_len + len(http_payload)
            if pkt.ipv4:
                pkt.ipv4.ident = (pkt.ipv4.ident + 1) & 0xffff

            # Set seq number matching configuration
            cfg = self.bypass_config
            if cfg.seq_offset_type == "classic":
                pkt.tcp.seq_num = (connection.syn_seq + 1 - len(http_payload)) & 0xffffffff
            elif cfg.seq_offset_type == "offset":
                pkt.tcp.seq_num = (connection.syn_seq + 1 + cfg.seq_offset_val) & 0xffffffff
            elif cfg.seq_offset_type == "abs":
                pkt.tcp.seq_num = cfg.seq_offset_val & 0xffffffff
            else:
                pkt.tcp.seq_num = (connection.syn_seq + 1 - len(http_payload)) & 0xffffffff

            self._send_fake_packet(pkt, True)
            logger.debug("Sent fake HTTP probe for %s", connection.id)
        except Exception as e:
            logger.debug("Error sending fake HTTP: %s", e)

    def _send_fake_rst(self, base_packet: Packet, connection: FakeInjectiveConnection):
        try:
            pkt = base_packet
            pkt.tcp.rst = True
            pkt.tcp.syn = False
            pkt.tcp.fin = False
            pkt.tcp.ack = False
            pkt.tcp.psh = False
            pkt.tcp.payload = b""
            pkt.ip.packet_len = pkt.ip.header_len + pkt.tcp.header_len
            if pkt.ipv4:
                pkt.ipv4.ident = (pkt.ipv4.ident + 2) & 0xffff
            pkt.tcp.seq_num = (connection.syn_seq + 1 + len(connection.fake_data)) & 0xffffffff
            self._send_fake_packet(pkt, True)
            logger.debug("Sent fake RST poison packet for %s", connection.id)
        except Exception as e:
            logger.debug("Error sending fake RST: %s", e)

    def fake_send_logic(self, packet: Packet, connection: FakeInjectiveConnection):
        with connection.thread_lock:
            if not connection.monitor:
                return

            cfg = self.bypass_config

            # 1. Fake HTTP probe if enabled
            if cfg.fake_http in ("get", "head"):
                self._send_fake_http(packet, connection, method=cfg.fake_http)

            # 2. Main Fake TLS ClientHello Packet
            packet.tcp.psh = True
            packet.tcp.ack = True
            packet.tcp.syn = False
            packet.tcp.rst = False
            packet.tcp.fin = False
            packet.tcp.payload = connection.fake_data
            packet.ip.packet_len = packet.ip.header_len + packet.tcp.header_len + len(connection.fake_data)
            if packet.ipv4:
                packet.ipv4.ident = (packet.ipv4.ident + 1) & 0xffff

            # Set Sequence Number based on offset
            if cfg.seq_offset_type == "classic":
                packet.tcp.seq_num = (connection.syn_seq + 1 - len(packet.tcp.payload)) & 0xffffffff
            elif cfg.seq_offset_type == "offset":
                packet.tcp.seq_num = (connection.syn_seq + 1 + cfg.seq_offset_val) & 0xffffffff
            elif cfg.seq_offset_type == "abs":
                packet.tcp.seq_num = cfg.seq_offset_val & 0xffffffff
            else:
                packet.tcp.seq_num = (connection.syn_seq + 1 - len(packet.tcp.payload)) & 0xffffffff

            connection.fake_sent = True
            self._send_fake_packet(packet, True)

            # 3. Fake RST state poisoning if enabled
            if cfg.fake_rst:
                self._send_fake_rst(packet, connection)

            # Release monitor immediately so real traffic starts flowing
            connection.monitor = False
            connection.t2a_msg = "fake_sent_direct"
            connection.running_loop.call_soon_threadsafe(connection.t2a_event.set)

    def on_unexpected_packet(self, packet: Packet, connection: FakeInjectiveConnection, info_m: str):
        logger.debug("%s: %s", info_m, connection.id)
        connection.monitor = False
        connection.t2a_msg = "released"
        connection.running_loop.call_soon_threadsafe(connection.t2a_event.set)
        try:
            self.w.send(packet, False)
        except Exception:
            pass

    def on_inbound_packet(self, packet: Packet, connection: FakeInjectiveConnection):
        if connection.syn_seq == -1:
            self.on_unexpected_packet(packet, connection, "unexpected inbound packet, no syn sent")
            return

        # Inbound SYN-ACK
        if packet.tcp.ack and packet.tcp.syn and not packet.tcp.rst and not packet.tcp.fin and len(packet.tcp.payload) == 0:
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if connection.syn_ack_seq != -1 and connection.syn_ack_seq != seq_num:
                self.on_unexpected_packet(packet, connection, "syn-ack seq change")
                return
            if ack_num != ((connection.syn_seq + 1) & 0xffffffff):
                self.on_unexpected_packet(packet, connection, "syn-ack ack mismatch")
                return
            connection.syn_ack_seq = seq_num
            self.w.send(packet, False)
            return

        # Inbound ACK for fake data
        if packet.tcp.ack and not packet.tcp.syn and not packet.tcp.rst and not packet.tcp.fin and len(packet.tcp.payload) == 0 and connection.fake_sent:
            connection.monitor = False
            connection.t2a_msg = "fake_data_ack_recv"
            connection.running_loop.call_soon_threadsafe(connection.t2a_event.set)
            return

        # Pass through other packets
        self.w.send(packet, False)

    def on_outbound_packet(self, packet: Packet, connection: FakeInjectiveConnection):
        if connection.sch_fake_sent:
            self.w.send(packet, False)
            return

        # Outbound SYN
        if packet.tcp.syn and not packet.tcp.ack and not packet.tcp.rst and not packet.tcp.fin and len(packet.tcp.payload) == 0:
            seq_num = packet.tcp.seq_num
            connection.syn_seq = seq_num
            self.w.send(packet, False)
            return

        # Outbound ACK completing 3-way handshake
        if packet.tcp.ack and not packet.tcp.syn and not packet.tcp.rst and not packet.tcp.fin and len(packet.tcp.payload) == 0:
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if connection.syn_seq == -1 or ((connection.syn_seq + 1) & 0xffffffff) != seq_num:
                self.on_unexpected_packet(packet, connection, "outbound ack seq mismatch")
                return
            if connection.syn_ack_seq == -1 or ack_num != ((connection.syn_ack_seq + 1) & 0xffffffff):
                self.on_unexpected_packet(packet, connection, "outbound ack ack mismatch")
                return

            self.w.send(packet, False)
            connection.sch_fake_sent = True
            # In original code: threading.Thread(target=self.fake_send_thread, args=(packet, connection), daemon=True).start()
            # with time.sleep(0.001) so the outbound handshake ACK leaves the OS before the fake packet is sent!
            def _async_send_fake():
                time.sleep(0.001)
                self.fake_send_logic(packet, connection)

            threading.Thread(target=_async_send_fake, daemon=True).start()
            return

        self.w.send(packet, False)

    def inject(self, packet: Packet):
        try:
            if packet.is_inbound:
                c_id = (packet.ip.dst_addr, packet.tcp.dst_port, packet.ip.src_addr, packet.tcp.src_port)
                connection = self.connections.get(c_id)
                if not connection:
                    self.w.send(packet, False)
                    return
                with connection.thread_lock:
                    if not connection.monitor:
                        self.w.send(packet, False)
                        return
                    self.on_inbound_packet(packet, connection)
            elif packet.is_outbound:
                c_id = (packet.ip.src_addr, packet.tcp.src_port, packet.ip.dst_addr, packet.tcp.dst_port)
                connection = self.connections.get(c_id)
                if not connection:
                    self.w.send(packet, False)
                    return
                with connection.thread_lock:
                    if not connection.monitor:
                        self.w.send(packet, False)
                        return
                    self.on_outbound_packet(packet, connection)
            else:
                self.w.send(packet, False)
        except Exception as e:
            logger.debug("Inject exception: %s", e)
            try:
                self.w.send(packet, False)
            except Exception:
                pass
