import ctypes
from ctypes import wintypes
import logging
import socket
from typing import Optional

logger = logging.getLogger("NpcapTools")

# Load Npcap wpcap.dll
try:
    wpcap = ctypes.CDLL("wpcap.dll")
    NPCAP_AVAILABLE = True
except Exception:
    wpcap = None
    NPCAP_AVAILABLE = False


class pcap_if(ctypes.Structure):
    pass


pcap_if._fields_ = [
    ("next", ctypes.POINTER(pcap_if)),
    ("name", ctypes.c_char_p),
    ("description", ctypes.c_char_p),
    ("addresses", ctypes.c_void_p),
    ("flags", ctypes.c_uint32),
]


class sockaddr(ctypes.Structure):
    _fields_ = [
        ("sa_family", ctypes.c_uint16),
        ("sa_data", ctypes.c_char * 14),
    ]


class sockaddr_in(ctypes.Structure):
    _fields_ = [
        ("sin_family", ctypes.c_uint16),
        ("sin_port", ctypes.c_uint16),
        ("sin_addr", ctypes.c_uint32),
        ("sin_zero", ctypes.c_char * 8),
    ]


class pcap_addr(ctypes.Structure):
    pass


pcap_addr._fields_ = [
    ("next", ctypes.POINTER(pcap_addr)),
    ("addr", ctypes.POINTER(sockaddr)),
    ("netmask", ctypes.POINTER(sockaddr)),
    ("broadaddr", ctypes.POINTER(sockaddr)),
    ("dstaddr", ctypes.POINTER(sockaddr)),
]


def list_npcap_interfaces() -> list[dict]:
    if not NPCAP_AVAILABLE:
        return []

    results = []
    alldevs = ctypes.POINTER(pcap_if)()
    errbuf = ctypes.create_string_buffer(256)
    ret = wpcap.pcap_findalldevs(ctypes.byref(alldevs), errbuf)
    if ret != 0:
        logger.warning("pcap_findalldevs error: %s", errbuf.value.decode("latin1", errors="ignore"))
        return []

    curr = alldevs
    while curr:
        dev = curr.contents
        name = dev.name.decode("latin1") if dev.name else ""
        desc = dev.description.decode("latin1", errors="ignore") if dev.description else ""

        # Extract IPv4 addresses
        ips = []
        addr_ptr = ctypes.cast(dev.addresses, ctypes.POINTER(pcap_addr))
        while addr_ptr:
            addr_item = addr_ptr.contents
            if addr_item.addr:
                sa = addr_item.addr.contents
                if sa.sa_family == socket.AF_INET:
                    sin = ctypes.cast(addr_item.addr, ctypes.POINTER(sockaddr_in)).contents
                    ip_bytes = sin.sin_addr.to_bytes(4, "little")
                    ip_str = socket.inet_ntoa(ip_bytes)
                    ips.append(ip_str)
            addr_ptr = addr_item.next

        results.append({
            "name": name,
            "description": desc,
            "ips": ips
        })
        curr = dev.next

    wpcap.pcap_freealldevs(alldevs)
    return results


def find_npcap_dev_by_ip(target_ip: str) -> Optional[dict]:
    interfaces = list_npcap_interfaces()
    for iface in interfaces:
        if target_ip in iface["ips"]:
            return iface
    return None


def get_mac_by_arp(target_ip: str, src_ip: str = "0.0.0.0") -> Optional[bytes]:
    try:
        iphlpapi = ctypes.windll.iphlpapi
        dest = socket.inet_aton(target_ip)
        src = socket.inet_aton(src_ip)
        dest_ip = int.from_bytes(dest, "little")
        src_ip_val = int.from_bytes(src, "little")
        mac = (ctypes.c_ubyte * 6)()
        mac_len = ctypes.c_ulong(6)
        ret = iphlpapi.SendARP(dest_ip, src_ip_val, ctypes.byref(mac), ctypes.byref(mac_len))
        if ret == 0:
            return bytes(mac)
    except Exception as e:
        logger.debug("SendARP failed: %s", e)
    return None


class NpcapDirectSender:
    def __init__(self, dev_name: str, src_mac: Optional[bytes] = None, gw_mac: Optional[bytes] = None):
        self.dev_name = dev_name
        self.src_mac = src_mac
        self.gw_mac = gw_mac
        self.pcap_handle = None
        self.datalink = 1  # default DLT_EN10MB

        if not NPCAP_AVAILABLE:
            raise RuntimeError("Npcap is not installed or wpcap.dll not found")

        errbuf = ctypes.create_string_buffer(256)
        wpcap.pcap_open_live.restype = ctypes.c_void_p
        wpcap.pcap_open_live.argtypes = [
            ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p
        ]
        self.pcap_handle = wpcap.pcap_open_live(
            dev_name.encode("latin1"), 65536, 1, 10, errbuf
        )
        if not self.pcap_handle:
            raise RuntimeError(f"Failed to open Npcap device {dev_name}: {errbuf.value.decode('latin1', errors='ignore')}")

        wpcap.pcap_datalink.restype = ctypes.c_int
        wpcap.pcap_datalink.argtypes = [ctypes.c_void_p]
        self.datalink = wpcap.pcap_datalink(self.pcap_handle)

        wpcap.pcap_sendpacket.restype = ctypes.c_int
        wpcap.pcap_sendpacket.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]

        wpcap.pcap_close.restype = None
        wpcap.pcap_close.argtypes = [ctypes.c_void_p]

        logger.debug("Opened Npcap device %s, datalink: %d", dev_name, self.datalink)

    def send_ip_packet(self, ip_bytes: bytes) -> bool:
        if not self.pcap_handle:
            return False

        # If Ethernet, prepend 14-byte Ethernet header
        if self.datalink == 1:
            dest = self.gw_mac or (b"\xff" * 6)
            src = self.src_mac or (b"\x00" * 6)
            eth_header = dest + src + b"\x08\x00"  # EtherType 0x0800 = IPv4
            frame = eth_header + ip_bytes
        else:
            frame = ip_bytes

        ret = wpcap.pcap_sendpacket(self.pcap_handle, frame, len(frame))
        return ret == 0

    def inject_fake_connection(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int,
                               fake_payload: bytes, config):
        try:
            import scapy.all as scapy
            from utils.packet_templates import HttpProbeMaker

            src_mac_str = ':'.join(f'{b:02x}' for b in self.src_mac) if self.src_mac else None
            gw_mac_str = ':'.join(f'{b:02x}' for b in self.gw_mac) if self.gw_mac else None

            # 1. Fake HTTP probe if requested
            http_mode = getattr(config, "fake_http", "none")
            if http_mode in ("get", "head"):
                if http_mode == "head":
                    http_data = f"HEAD / HTTP/1.1\r\nHost: {config.fake_sni}\r\nUser-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n".encode()
                else:
                    http_data = HttpProbeMaker.get_fake_get(config.fake_sni)
                pkt = scapy.IP(src=src_ip, dst=dst_ip) / scapy.TCP(sport=src_port, dport=dst_port, flags="PA") / http_data
                if self.datalink == 1 and src_mac_str and gw_mac_str:
                    frame = scapy.Ether(src=src_mac_str, dst=gw_mac_str) / pkt
                    scapy.sendp(frame, iface=self.dev_name, verbose=False)
                else:
                    scapy.send(pkt, iface=self.dev_name, verbose=False)

            # 2. Fake TLS ClientHello
            tcp_kwargs = {"sport": src_port, "dport": dst_port, "flags": "PA"}
            o_type = getattr(config, "seq_offset_type", "classic")
            if o_type == "offset":
                tcp_kwargs["seq"] = (1000000 + config.seq_offset_val) & 0xffffffff
            elif o_type == "abs":
                tcp_kwargs["seq"] = config.seq_offset_val & 0xffffffff
            else:
                tcp_kwargs["seq"] = (1000000 - len(fake_payload)) & 0xffffffff

            pkt = scapy.IP(src=src_ip, dst=dst_ip) / scapy.TCP(**tcp_kwargs) / fake_payload

            if self.datalink == 1 and src_mac_str and gw_mac_str:
                frame = scapy.Ether(src=src_mac_str, dst=gw_mac_str) / pkt
                scapy.sendp(frame, iface=self.dev_name, verbose=False)
            else:
                scapy.send(pkt, iface=self.dev_name, verbose=False)

            # 3. Fake RST if requested
            if getattr(config, "fake_rst", False):
                pkt_rst = scapy.IP(src=src_ip, dst=dst_ip) / scapy.TCP(sport=src_port, dport=dst_port, flags="R")
                if self.datalink == 1 and src_mac_str and gw_mac_str:
                    frame = scapy.Ether(src=src_mac_str, dst=gw_mac_str) / pkt_rst
                    scapy.sendp(frame, iface=self.dev_name, verbose=False)
                else:
                    scapy.send(pkt_rst, iface=self.dev_name, verbose=False)

        except Exception as e:
            logger.debug("Npcap direct inject exception: %s", e)

    def send_raw(self, packet_bytes: bytes) -> bool:
        if not self.pcap_handle:
            return False
        ret = wpcap.pcap_sendpacket(self.pcap_handle, packet_bytes, len(packet_bytes))
        return ret == 0

    def close(self):
        if self.pcap_handle:
            try:
                wpcap.pcap_close(self.pcap_handle)
            except Exception:
                pass
            self.pcap_handle = None
