from .core import AppletBase

class Teapot(AppletBase):
    def __init__(self, connection=None):
        super().__init__("B00B5111CA01", connection)

    def get_data(self):
        return self.request("B0A10000")

    def put_data(self, d):
        data = bytes([len(d)])+d.encode()
        return self.request("B0A20000"+data.hex())
