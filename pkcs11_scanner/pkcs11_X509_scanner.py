from pkcs11_cryptography_keys import (
    MechanismProperties,
    MultiCertificateContainer,
    TokenProperties,
)
from PyKCS11 import PyKCS11Lib


class PKCS11X506Scanner(object):
    def __init__(
        self,
        library: PyKCS11Lib,
        filter: dict | None = None,
        add_certificate: bool = False,
    ) -> None:
        self._library = library
        self._filter = filter
        self._add_certificate = add_certificate

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
        ret["slots"] = list()
        slots = self._library.getSlotList(tokenPresent=True)
        for sl in slots:
            tp = TokenProperties.read_from_slot(self._library, sl)
            label = tp.get_label()
            login_required = tp.is_login_required()
            token_protected_path = tp.has_proteced_authentication_path()
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
                    if self._filter is not None:
                        conformant = await cert_props.has_conformant_key_usage(
                            self._filter
                        )
                    else:
                        conformant = True
                    if conformant:
                        cert_data = cert_props.get_certificate_data(
                            self._add_certificate
                        )
                        if cert_data is not None:
                            cert_data["key_id"] = key_id
                            cert_data["key_label"] = key_label
                            certs.append(cert_data)

            if len(certs) > 0:
                slot = {
                    "token": {
                        "label": label,
                        "token_login_required": login_required,
                        "token_protected_path": token_protected_path,
                        "certificates": certs,
                    }
                }
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
