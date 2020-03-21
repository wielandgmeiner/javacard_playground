from .helpers import AppletBase

class Teapot(AppletBase):
    def __init__(self, connection=None):
        super().__init__("B00B5111CA01", connection)