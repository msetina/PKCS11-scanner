from queue import Queue

from PyKCS11 import PyKCS11Lib

from .pkcs11_card_scanner import PKCS11CardScanner
from .pkcs11_check_thread import PKCS11CheckThread
from .pkcs11_scan import PKCS11Scan


class PKCS11CheckCardScanThread(PKCS11CheckThread):
    def __init__(
        self,
        library_path: str,
        comm_queue: Queue,
        refresh_seconds: int = 1,
    ):
        super().__init__(library_path, comm_queue, refresh_seconds)

    async def _on_token_present(self, library: PyKCS11Lib):
        scanner = PKCS11CardScanner(library)
        data = await scanner.scan_from_library()
        ret = PKCS11Scan(data)
        return ret
