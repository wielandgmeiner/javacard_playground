from .core import SecureAppletBase

class MemoryCard(SecureAppletBase):
    def __init__(self, connection=None):
        super().__init__("B00B5111CB01", connection)

    def get_secret_data(self):
        return self.secure_request(b'\x05\x00')

    def put_secret_data(self, d):
        return self.secure_request(b'\x05\x01'+d)