class PKCS11CheckError(object):
    def __init__(self, msg: str):
        self._msg = msg

    def __str__(self):
        return self._msg
