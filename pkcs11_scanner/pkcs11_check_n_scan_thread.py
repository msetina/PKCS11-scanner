from queue import Queue

from PyKCS11 import PyKCS11Lib

from .pkcs11_check_thread import PKCS11CheckThread
from .pkcs11_scan import PKCS11Scan
from .pkcs11_scanner import PKCS11Scanner


class PKCS11ChecknScanThread(PKCS11CheckThread):
    def __init__(
        self, library_path: str, comm_queue: Queue, refresh_seconds: int = 1
    ):
        super().__init__(library_path, comm_queue, refresh_seconds)

    async def _on_token_present(self, library: PyKCS11Lib):
        scanner = PKCS11Scanner(library)
        data = await scanner.scan_from_library()
        ret = PKCS11Scan(data)
        return ret
