import struct


class ClientHelloMaker:
    tls_ch_template_str = "1603010200010001fc030341d5b549d9cd1adfa7296c8418d157dc7b624c842824ff493b9375bb48d34f2b20bf018bcc90a7c89a230094815ad0c15b736e38c01209d72d282cb5e2105328150024130213031301c02cc030c02bc02fcca9cca8c024c028c023c027009f009e006b006700ff0100018f0000000b00090000066d63692e6972000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000010000e000c02683208687474702f312e310016000000170000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b00050403040303002d00020101003300260024001d0020435bacc4d05f9d41fef44ab3ad55616c36e0613473e2338770efdaa98693d217001500d5000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    tls_ch_template = bytes.fromhex(tls_ch_template_str)
    template_sni = "mci.ir".encode()
    static1 = tls_ch_template[:11]
    static2 = b"\x20"
    static3 = tls_ch_template[76:120]
    static4 = tls_ch_template[127 + len(template_sni):262 + len(template_sni)]
    static5 = b"\x00\x15"
    ##############
    tls_change_cipher = b"\x14\x03\x03\x00\x01\x01"
    tls_app_data_header = b"\x17\x03\x03"

    @classmethod
    def get_client_hello_with(cls, rnd: bytes, sess_id: bytes, target_sni: bytes,
                              key_share: bytes) -> bytes:  # rnd,sess_id,key_share: 32 bytes
        server_name_ext = struct.pack("!H", len(target_sni) + 5) + struct.pack("!H",
                                                                               len(target_sni) + 3) + b"\x00" + struct.pack(
            "!H", len(target_sni)) + target_sni
        padding_ext = struct.pack("!H", 219 - len(target_sni)) + (b"\x00" * (219 - len(target_sni)))
        return cls.static1 + rnd + cls.static2 + sess_id + cls.static3 + server_name_ext + cls.static4 + key_share + cls.static5 + padding_ext
        # rnd-> [11:43)  sess_id-> [44:76) key_share-> [262+len(target_sni):294+len(target_sni))

    @classmethod
    def get_client_hello_with_ech(cls, rnd: bytes, sess_id: bytes, target_sni: bytes,
                                  key_share: bytes, outer_sni: bytes = b"cloudflare.com") -> bytes:
        # Build standard ClientHello with outer_sni
        base_ch = cls.get_client_hello_with(rnd, sess_id, outer_sni, key_share)
        
        # Build ECH extension (0xfe0d)
        kdf_aead = struct.pack("!HH", 0x0001, 0x0001)
        config_id = b"\x01"
        enc = rnd[:32]
        enc_field = struct.pack("!H", len(enc)) + enc
        # Encrypted inner hello mock with target_sni
        inner_hello_mock = b"\x00" * 96 + target_sni + b"\x00" * 32
        ech_payload_field = struct.pack("!H", len(inner_hello_mock)) + inner_hello_mock
        ech_data = kdf_aead + config_id + enc_field + ech_payload_field
        ech_ext = struct.pack("!HH", 0xfe0d, len(ech_data)) + ech_data
        
        # Update record length and handshake length
        rec_len = struct.unpack("!H", base_ch[3:5])[0] + len(ech_ext)
        hs_len = int.from_bytes(base_ch[6:9], "big") + len(ech_ext)
        
        # Update extension length (found at offset 120 in base template)
        # 5 (rec) + 4 (hs) + 2 (ver) + 32 (rnd) + 1 + 32 (sess) + 2 + 36 (ciphers) + 1 + 1 (comp) + 2 (ext_len) = 118
        ext_len_offset = 118
        ext_len = struct.unpack("!H", base_ch[ext_len_offset:ext_len_offset + 2])[0] + len(ech_ext)
        
        buf = bytearray(base_ch)
        buf[3:5] = struct.pack("!H", rec_len)
        buf[6:9] = hs_len.to_bytes(3, "big")
        buf[ext_len_offset:ext_len_offset + 2] = struct.pack("!H", ext_len)
        buf.extend(ech_ext)
        return bytes(buf)

    @staticmethod
    def is_tls_client_hello(data: bytes) -> bool:
        return len(data) >= 9 and data[0] == 0x16 and data[5] == 0x01

    @staticmethod
    def find_sni(data: bytes) -> tuple[int, int, str]:
        """Returns (sni_offset, sni_len, sni_str) or (-1, 0, '') if not found."""
        if len(data) < 43 or data[0] != 0x16:
            return -1, 0, ""
        try:
            idx = 43
            if idx >= len(data):
                return -1, 0, ""
            sess_id_len = data[idx]
            idx += 1 + sess_id_len
            if idx + 2 > len(data):
                return -1, 0, ""
            cipher_len = struct.unpack("!H", data[idx:idx + 2])[0]
            idx += 2 + cipher_len
            if idx + 1 > len(data):
                return -1, 0, ""
            comp_len = data[idx]
            idx += 1 + comp_len
            if idx + 2 > len(data):
                return -1, 0, ""
            ext_total_len = struct.unpack("!H", data[idx:idx + 2])[0]
            idx += 2
            ext_end = min(idx + ext_total_len, len(data))
            while idx + 4 <= ext_end:
                ext_type, ext_len = struct.unpack("!HH", data[idx:idx + 4])
                idx += 4
                if ext_type == 0:  # server_name
                    if idx + 5 <= len(data):
                        name_len = struct.unpack("!H", data[idx + 3:idx + 5])[0]
                        name_offset = idx + 5
                        if name_offset + name_len <= len(data):
                            sni = data[name_offset:name_offset + name_len].decode("latin1", errors="ignore")
                            return name_offset, name_len, sni
                idx += ext_len
        except Exception:
            pass
        return -1, 0, ""

    @staticmethod
    def split_for_sni_fragmentation(data: bytes, split_mode: str = "sni") -> list[bytes]:
        """
        Splits ClientHello for DPI fragmentation bypass.
        Modes:
          - 'record_header': split at byte 5 (record header)
          - 'sni': split right inside the SNI domain name (e.g. 2nd byte of SNI)
          - 'tiny': split into tiny 2-byte chunk then remainder
        """
        if not ClientHelloMaker.is_tls_client_hello(data):
            return [data]
        
        offset, sni_len, _ = ClientHelloMaker.find_sni(data)
        split_point = 5  # default after TLS record header
        
        if split_mode == "sni" and offset > 0 and sni_len > 2:
            # Split inside the SNI host name (e.g. 2 bytes into the hostname)
            split_point = offset + 2
        elif split_mode == "tiny":
            split_point = 2
        elif split_mode == "mid" and len(data) > 40:
            split_point = 40
            
        if 0 < split_point < len(data):
            return [data[:split_point], data[split_point:]]
        return [data]


class HttpProbeMaker:
    @staticmethod
    def get_fake_get(host: str) -> bytes:
        return (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n"
            f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            f"Accept-Language: en-US,en;q=0.9\r\n"
            f"Connection: keep-alive\r\n\r\n"
        ).encode()

    @classmethod
    def parse_client_hello(cls, client_hello_bytes: bytes):
        assert len(client_hello_bytes) == 517
        rnd = client_hello_bytes[11:43]
        sess_id = client_hello_bytes[44:76]
        tls_sni = client_hello_bytes[127:127 + (struct.unpack("!H", client_hello_bytes[125:127])[0])].decode()
        ks_ind = 262 + len(tls_sni)
        key_share = client_hello_bytes[ks_ind:ks_ind + 32]
        assert cls.get_client_hello_with(rnd, sess_id, tls_sni, key_share) == client_hello_bytes
        return rnd, sess_id, tls_sni, key_share

    @classmethod
    def get_client_response_with(cls, app_data1: bytes):
        return cls.tls_change_cipher + cls.tls_app_data_header + struct.pack("!H", len(app_data1)) + app_data1

    @classmethod
    def parse_client_response(cls, client_response_bytes: bytes):
        assert len(client_response_bytes) >= 32
        app_data1 = client_response_bytes[11:]
        assert cls.get_client_response_with(app_data1) == client_response_bytes
        return app_data1


class ServerHelloMaker:
    tls_sh_template_str = "160303007a0200007603035e39ed63ad58140fbd12af1c6a37c879299a39461b308d63cb1dae291c5b69702057d2a640c5ca53fed0f24491baaf96347f12db603fd1babe6bc3ad0b6fbde406130200002e002b0002030400330024001d0020d934ed49a1619be820856c4986e865c5b0e4eb188ebd30193271e8171152eb4e"
    tls_sh_template = bytes.fromhex(tls_sh_template_str)
    static1 = tls_sh_template[:11]
    static2 = b"\x20"
    static3 = tls_sh_template[76:95]
    tls_change_cipher = b"\x14\x03\x03\x00\x01\x01"
    tls_app_data_header = b"\x17\x03\x03"

    @classmethod
    def get_server_hello_with(cls, rnd: bytes, sess_id: bytes, key_share: bytes, app_data1: bytes):
        return cls.static1 + rnd + cls.static2 + sess_id + cls.static3 + key_share + cls.tls_change_cipher + cls.tls_app_data_header + struct.pack(
            "!H", len(app_data1)) + app_data1

    @classmethod
    def parse_server_hello(cls, server_hello_bytes: bytes):
        assert len(server_hello_bytes) >= 159
        rnd = server_hello_bytes[11:43]
        sess_id = server_hello_bytes[44:76]
        key_share = server_hello_bytes[95:127]
        app_data1 = server_hello_bytes[138:]
        assert cls.get_server_hello_with(rnd, sess_id, key_share, app_data1) == server_hello_bytes
        return rnd, sess_id, key_share, app_data1
