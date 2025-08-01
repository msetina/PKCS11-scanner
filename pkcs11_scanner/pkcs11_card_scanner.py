from pkcs11_cryptography_keys import (
    LibraryProperties,
    MechanismProperties,
    MultiCertificateContainer,
    SlotProperties,
    TokenProperties,
)
from PyKCS11 import PyKCS11Lib


class PKCS11CardScanner(object):
    def __init__(self, library: PyKCS11Lib) -> None:
        self._library = library

    @classmethod
    def from_library_path(cls, library_path: str | None = None):
        library = PyKCS11Lib()
        if library_path is not None:
            library.load(library_path)
        else:
            library.load()
        return cls(library)

    async def scan_from_library(
        self,
        pin: str | None = None,
    ) -> dict:
        ret: dict = {}
        login_required = False

        lp = LibraryProperties.read_from_slot(self._library)
        for tag, val in lp.gen_tags():
            ret[tag] = val
        slots = self._library.getSlotList(tokenPresent=True)
        ret["slots"] = []
        for sl in slots:
            slot = {}
            tp = TokenProperties.read_from_slot(self._library, sl)
            if tp.is_login_required():
                login_required = True
            if tp.is_initialized():
                sp = SlotProperties.read_from_slot(self._library, sl)
                for tag, val in sp.gen_tags():
                    slot[tag] = val
                slot["token"] = {}
                # slot["token"]["max_pin_length"] = tp.get_max_pin_length()
                # slot["token"]["min_pin_length"] = tp.get_min_pin_length()
                for tag, val in tp.gen_tags():
                    slot["token"][tag] = val
                slot["token"]["HW_slot"] = sp.is_hardware_slot()
                slot["token"]["removable_slot"] = sp.is_removable()
                certs = list()
                mcc = await MultiCertificateContainer.read_slot(
                    self._library, sl, login_required, pin
                )
                if mcc is not None:
                    async for (
                        key_id,
                        key_label,
                        cert_props,
                    ) in mcc.gen_certificates_for_token():
                        cert_data = cert_props.get_certificate_data()
                        if cert_data is not None:
                            cert_data["key_id"] = key_id
                            cert_data["key_label"] = key_label
                            certs.append(cert_data)
                    if len(certs) > 0:
                        slot["token"]["certificates"] = certs
                slot["token"]["mechanisms"] = {}
                for mp in MechanismProperties.gen_mechanism_properties(
                    self._library, sl
                ):
                    slot["token"]["mechanisms"][mp.get_mechanism_type()] = {}
                    for tag, val in mp.gen_tags():
                        slot["token"]["mechanisms"][mp.get_mechanism_type()][
                            tag
                        ] = val
                ret["slots"].append(slot)

        return ret
