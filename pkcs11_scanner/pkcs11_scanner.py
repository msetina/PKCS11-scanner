from pkcs11_cryptography_keys import (
    KeyTypes,
    LibraryProperties,
    MechanismProperties,
    SlotProperties,
    TokenProperties,
    read_key_usage_from_key,
)
from PyKCS11 import (
    CKA_CLASS,
    CKA_ID,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKF_SERIAL_SESSION,
    CKK_EC,
    CKK_RSA,
    CKO_CERTIFICATE,
    CKO_DATA,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
    CKO_SECRET_KEY,
    PyKCS11Lib,
)

PKCS11_type_translation: dict[str, int] = {
    "certificate": CKO_CERTIFICATE,
    "data": CKO_DATA,
    "private": CKO_PRIVATE_KEY,
    "public": CKO_PUBLIC_KEY,
    "secret-key": CKO_SECRET_KEY,
}

PKCS11_key_type_translation: dict[int, KeyTypes] = {
    CKK_EC: KeyTypes.EC,
    CKK_RSA: KeyTypes.RSA,
}


class PKCS11Scanner(object):
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

    async def __read_keys(
        self,
        library: PyKCS11Lib,
        slot: int,
        tp: str,
        login_required: bool,
        pin: str | None,
    ):
        ret = []
        template = []
        if tp in PKCS11_type_translation:
            tp_v = PKCS11_type_translation[tp]
            template.append((CKA_CLASS, tp_v))
            session = library.openSession(slot, CKF_SERIAL_SESSION)
            logged_in: bool = False
            try:
                if login_required and pin is not None:
                    session.login(pin)
                    logged_in = True
                keys = session.findObjects(template)
                for key in keys:
                    key_data = {}
                    attrs = session.getAttributeValue(
                        key, [CKA_LABEL, CKA_ID, CKA_KEY_TYPE]
                    )
                    label = attrs[0]
                    key_id = bytes(attrs[1])
                    kt = attrs[2]
                    key_data["label"] = label
                    key_data["id"] = key_id
                    key_data["type"] = tp
                    kt_i = PKCS11_key_type_translation.get(kt, None)
                    if kt_i is not None:
                        key_data["key_type"] = kt_i
                    key_usage = read_key_usage_from_key(session, key)
                    if key_usage is not None:
                        key_data["key_usage"] = key_usage
                    ret.append(key_data)
            finally:
                if logged_in:
                    session.logout()
                session.closeSession()
        return ret

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
                slot["token"]["private keys"] = await self.__read_keys(
                    self._library, sl, "private", login_required, pin
                )
                slot["token"]["public keys"] = await self.__read_keys(
                    self._library, sl, "public", login_required, pin
                )
                slot["token"]["certificates"] = await self.__read_keys(
                    self._library,
                    sl,
                    "certificate",
                    login_required,
                    pin,
                )
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
