import logging
from abc import ABC, abstractmethod
from pydivert import WinDivert, Packet

logger = logging.getLogger("TcpInjector")


class TcpInjector(ABC):
    def __init__(self, w_filter: str):
        self.w_filter = w_filter
        self.w: WinDivert | None = None
        self.running = False

    @abstractmethod
    def inject(self, packet: Packet):
        pass

    def run(self):
        self.running = True
        try:
            self.w = WinDivert(self.w_filter)
            with self.w:
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
            logger.error("WinDivert requires Administrator privileges.")
            raise
        except Exception as e:
            logger.error("WinDivert loop error: %s", e)
        finally:
            self.running = False

    def stop(self):
        self.running = False
        try:
            if self.w and self.w.is_open:
                self.w.close()
        except Exception:
            pass
