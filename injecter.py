import logging
import sys
from abc import ABC, abstractmethod

logger = logging.getLogger("TcpInjector")

try:
    from pydivert import WinDivert, Packet
    HAS_PYDIVERT = True
except ImportError:
    WinDivert = None
    Packet = None
    HAS_PYDIVERT = False


class TcpInjector(ABC):
    def __init__(self, w_filter: str):
        self.w_filter = w_filter
        self.w = None
        self.running = False
        self.is_active = False

    @abstractmethod
    def inject(self, packet):
        pass

    def run(self):
        if not HAS_PYDIVERT:
            logger.info("pydivert is not available on this platform.")
            return

        self.running = True
        try:
            self.w = WinDivert(self.w_filter)
            with self.w:
                self.is_active = True
                while self.running:
                    try:
                        packet = self.w.recv(65575)
                        if not self.running:
                            break
                        self.inject(packet)
                    except Exception as e:
                        if not self.running:
                            break
                        logger.debug("WinDivert recv error: %s", e)
        except PermissionError:
            self.is_active = False
            logger.info("WinDivert requires Administrator. Operating via Npcap/Proxy mode.")
        except Exception as e:
            self.is_active = False
            logger.error("WinDivert loop error: %s", e)
        finally:
            self.running = False
            self.is_active = False

    def stop(self):
        self.running = False
        self.is_active = False
        try:
            if self.w and getattr(self.w, "is_open", False):
                self.w.close()
        except Exception:
            pass
