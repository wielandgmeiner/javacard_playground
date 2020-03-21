from smartcard import ATR
from smartcard.System import readers
from smartcard.CardConnection import CardConnection

def get_reader():
    """Returns first found reader """
    rarr=readers()
    if len(rarr) == 0:
        return None
    return rarr[0]

def get_connection(reader=None, protocol=CardConnection.T1_protocol):
    """Establish connection with a card"""
    if reader is None:
        reader = get_reader()
    if reader is None:
        return None
    connection = reader.createConnection()
    connection.connect(protocol)
    return connection

def maybe_fromhex(d):
    # check if we got a string or bytes
    if hasattr(d,"encode"):
        return list(bytes.fromhex(d))
    else:
        return d

def select_applet(connection, appletID):
    """Select an applet with appletID
    appletID can be either a hex-encoded string or byte sequence
    """
    data = maybe_fromhex(appletID)
    # Select:
    # CLA = 0x00
    # INS = 0xA4
    # P1 = 0x04
    # P2 = 0x00
    # Data = the instance AID
    cmd = [0x00, # CLA
           0xA4, # INS
           0x04, # P1
           0x00, # P2
           len(data), # Lc (content length)
          ] + data + [0x00]
    data, *sw = connection.transmit(cmd)
    data = bytes(data)
    sw = bytes(sw)
    if sw == b"\x90\x00":
        return data
    else:
        raise RuntimeError("Card responded with code %s and data \"%s\"" % (sw.hex(), data.hex()))

def request(connection, APDU):
    cmd = maybe_fromhex(APDU)
    data, *sw = connection.transmit(cmd)
    data = bytes(data)
    sw = bytes(sw)
    if sw == b"\x90\x00":
        return data
    else:
        raise RuntimeError("Card responded with code %s and data \"%s\"" % (sw.hex(), data.hex()))

class AppletBase:
    def __init__(self, AID, connection=None):
        self.AID = AID
        self.connection = connection

    def select(self):
        return select_applet(self.connection, self.AID)

    def request(self, APDU):
        return request(self.connection, APDU)

    def get_data(self):
        return self.request("B0A10000")

    def put_data(self, d):
        data = bytes([len(d)])+d.encode()
        return self.request("B0A20000"+data.hex())
