from .teapot import Teapot

class MemoryCard(Teapot):
    def __init__(self, connection=None):
        super().__init__(connection)
        self.AID = "B00B5111CB01"

    def get_random(self):
        return self.request("B1A20000")