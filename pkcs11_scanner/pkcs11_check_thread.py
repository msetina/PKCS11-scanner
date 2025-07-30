from asyncio import run as async_run
from asyncio import sleep as async_sleep
from queue import Queue
from threading import Event, Thread

from pkcs11_cryptography_keys import SlotProperties, TokenException
from PyKCS11 import CKF_DONT_BLOCK, CKR_NO_EVENT, PyKCS11Error, PyKCS11Lib

from .pkcs11_check_error import PKCS11CheckError


class PKCS11CheckThread(Thread):
    def __init__(
        self, library_path: str, comm_queue: Queue, refresh_seconds: int = 1
    ):
        super().__init__()
        self._library_path = library_path
        self._comm = comm_queue
        self._refresh_seconds = refresh_seconds
        self._stop_event = Event()

    def set_stop_event(self):
        self._stop_event.set()

    def run(self):
        async_run(self.async_run())

    async def async_run(self):
        library = PyKCS11Lib()
        library.load(self._library_path)
        running = True
        while running:
            try:
                if self._stop_event.is_set():
                    running = False
                else:
                    await self._check_slot_event(library)
                    await async_sleep(self._refresh_seconds)
            except PyKCS11Error as ne:
                if ne.value != CKR_NO_EVENT:
                    self._comm.put(PKCS11CheckError(str(ne)))
                await async_sleep(self._refresh_seconds)
            except Exception as ex:
                self._comm.put(PKCS11CheckError(str(ex)))
                running = False

    async def _check_slot_event(self, library):
        slot = library.waitForSlotEvent(CKF_DONT_BLOCK)
        sp = SlotProperties.read_from_slot(library, slot)
        self._comm.put(sp)
        if sp.is_token_present():
            ret_data = await self._on_token_present(library)
            if ret_data is not None and hasattr(ret_data, "has_data"):
                if ret_data.has_data():
                    # send tokens to queue
                    self._comm.put(ret_data)
                else:
                    raise TokenException(
                        "No token present. Please insert card."
                    )

    async def _on_token_present(self, library: PyKCS11Lib):
        return None
