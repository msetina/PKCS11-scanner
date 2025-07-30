from urllib.parse import quote, quote_from_bytes

from PyKCS11 import PyKCS11Lib

from .pkcs11_scanner import PKCS11Scanner

_translation = {
    "info": {
        "libraryDescription": "library-description",
        # "libraryVersion": "library-version",
        "manufacturerID": "library-manufacturer",
    },
    "slots": {
        "manufacturerID": "slot-manufacturer",
        "slotDescription": "slot-description",
    },
    "token": {
        "label": "token",
        "manufacturerID": "manufacturer",
        "model": "model",
        "serialNumber": "serial",
    },
    "object": {"object": "object", "id": "id", "type": "type"},
}


class PKCS11ScannerURI(PKCS11Scanner):
    def __init__(
        self,
        library: PyKCS11Lib,
        ignore_parents: list[str] | None = None,
    ) -> None:
        super().__init__(library)
        self._ignore_parents = (
            ignore_parents if ignore_parents is not None else []
        )

    @classmethod
    def from_library_path(
        cls,
        library_path: str | None = None,
        ignore_parents: list[str] | None = None,
    ):
        library = PyKCS11Lib()
        if library_path is not None:
            library.load(library_path)
        else:
            library.load()
        return cls(library, ignore_parents)

    async def __add_uris(
        self, parent: str, path: list | None, query: list, data: dict
    ):
        if parent in ["certificates", "public keys", "private keys"]:
            parent = "object"
        lpath = []
        if path is not None:
            lpath.extend(path)
        for k, v in data.items():
            if isinstance(v, dict):
                await self.__add_uris(k, lpath, query, v)
            elif isinstance(v, list):
                for a in v:
                    if isinstance(a, dict):
                        await self.__add_uris(k, lpath, query, a)
            else:
                if parent not in self._ignore_parents:
                    tag = _translation[parent].get(k, None)
                    if tag is not None:
                        if isinstance(v, bytes):
                            lpath.append("{0}=%{1}".format(tag, v.hex()))
                        else:
                            lpath.append("{0}={1}".format(tag, quote(v)))
        if len(lpath) > 0:
            data["uri"] = "pkcs11:{0}".format(";".join(lpath))
            if len(query) > 0:
                data["uri"] = "{0}?{1}".format(data["uri"], ";".join(query))

    async def scan_from_library(self, pin: str | None = None) -> dict:
        rez = await super().scan_from_library(pin)
        parent = "info"
        query = []
        # TODO fix this
        # if self._library is not None:
        #    query.append("module-path={0}".format(self._library))
        if pin is not None:
            query.append("pin-value={0}".format(pin))
        await self.__add_uris(parent, None, query, rez)
        return rez
