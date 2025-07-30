class PKCS11Scan(object):
    def __init__(self, data: dict | None = None):
        self._scan_data: dict = dict() if data is None else data

    def has_data(self) -> bool:
        return len(self._scan_data) > 0

    def get_token_labels(self):
        if "slots" in self._scan_data:
            for s in self._scan_data["slots"]:
                if "token" in s and "label" in s["token"]:
                    yield (s["token"]["label"])

    def get_HW_token_labels(self):
        if "slots" in self._scan_data:
            for s in self._scan_data["slots"]:
                if "token" in s and "label" in s["token"]:
                    if "HW_slot" in s["token"]:
                        if s["token"]["HW_slot"]:
                            yield (s["token"]["label"])

    def has_token_with_label(self, label: str) -> bool:
        if "slots" in self._scan_data:
            for s in self._scan_data["slots"]:
                if "token" in s and "label" in s["token"]:
                    if s["token"]["label"] == label:
                        return True
        return False

    def get_token_for_label(self, label: str) -> dict | None:
        if "slots" in self._scan_data:
            for s in self._scan_data["slots"]:
                if "token" in s and "label" in s["token"]:
                    if s["token"]["label"] == label:
                        return s["token"]
        return None
