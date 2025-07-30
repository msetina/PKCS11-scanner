from queue import Queue

from PyKCS11 import PyKCS11Lib

from .pkcs11_check_thread import PKCS11CheckThread
from .pkcs11_scan import PKCS11Scan
from .pkcs11_X509_scanner import PKCS11X506Scanner


class PKCS11CheckX509ScanThread(PKCS11CheckThread):
    def __init__(
        self,
        library_path: str,
        token_filter: dict | None,
        comm_queue: Queue,
        refresh_seconds: int = 1,
        add_certificate: bool = False,
    ):
        super().__init__(library_path, comm_queue, refresh_seconds)
        self._filter = token_filter
        self._add_certificate = add_certificate

    async def _on_token_present(self, library: PyKCS11Lib):
        scanner = PKCS11X506Scanner(
            library, self._filter, self._add_certificate
        )
        data = await scanner.scan_from_library()
        ret = PKCS11Scan(data)
        return ret
