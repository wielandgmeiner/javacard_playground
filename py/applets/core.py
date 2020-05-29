from .util import secp256k1

from smartcard import ATR
from smartcard.System import readers
from smartcard.CardConnection import CardConnection

import os, hashlib, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

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

class SecureAppletBase(AppletBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.iv = 0
        self.card_pubkey = None
        self.card_aes_key = None
        self.host_aes_key = None
        self.card_mac_key = None
        self.host_mac_key = None
        self.mode = "es"
        self.is_secure_channel_open = False

    def get_random(self):
        if self.is_secure_channel_open:
            return self.get_random_sc()
        else:
            return self.request("B0B10000")
        
    def get_card_pubkey(self):
        sec = self.request("B0B2000000")
        self.card_pubkey = secp256k1.ec_pubkey_parse(sec)
        return self.card_pubkey

    def establish_secure_channel(self, mode=None):
        # save mode for later - i.e. reestablish secure channel
        if mode is None:
            mode = self.mode
        else:
            self.mode = mode
        # check if we know pubkey already
        if self.card_pubkey is None:
            self.get_card_pubkey()
        # generate ephimerial key
        secret = os.urandom(32)
        host_prv = secret
        host_pub = secp256k1.ec_pubkey_create(secret)
        # ee mode - ask card to create ephimerial key and send it to us
        if mode=="ee":
            data = bytes([65])+secp256k1.ec_pubkey_serialize(host_pub, secp256k1.EC_UNCOMPRESSED)
            # get ephimerial pubkey from the card
            res = self.request("B0B40000"+data.hex())
            pub = secp256k1.ec_pubkey_parse(res[:65])
            secp256k1.ec_pubkey_tweak_mul(pub, secret)
            shared_secret = secp256k1.ec_pubkey_serialize(pub)[1:33]
            self.host_aes_key = hashlib.sha256(b'host_aes'+shared_secret).digest()
            self.card_aes_key = hashlib.sha256(b'card_aes'+shared_secret).digest()
            self.host_mac_key = hashlib.sha256(b'host_mac'+shared_secret).digest()
            self.card_mac_key = hashlib.sha256(b'card_mac'+shared_secret).digest()
            shared_fingerprint = hashlib.sha256(shared_secret).digest()[:4]
            recv_hmac = res[65:97]
            h = hmac.new(self.card_mac_key, digestmod='sha256')
            h.update(res[:65])
            expected_hmac = h.digest()
            if expected_hmac != recv_hmac:
                raise RuntimeError("Wrong HMAC. Got %s, expected %s"%(recv_hmac.hex(),expected_hmac.hex()))
            sig = secp256k1.ecdsa_signature_parse_der(res[97:])
            # in case card doesn't follow low s rule (but it should)
            sig = secp256k1.ecdsa_signature_normalize(sig)
            if not secp256k1.ecdsa_verify(sig, hashlib.sha256(res[:97]).digest(), self.card_pubkey):
                raise RuntimeError("Signature is invalid: %r", res[97:].hex())
        # se mode - use our ephimerial key with card's static key
        else:
            nonce_host = os.urandom(32)
            payload = secp256k1.ec_pubkey_serialize(host_pub, secp256k1.EC_UNCOMPRESSED)+nonce_host
            data = bytes([len(payload)])+payload
            # ugly copy
            pub = secp256k1.ec_pubkey_parse(secp256k1.ec_pubkey_serialize(self.card_pubkey))
            secp256k1.ec_pubkey_tweak_mul(pub, secret)
            shared_secret = secp256k1.ec_pubkey_serialize(pub)[1:33]
            res = self.request("B0B30000"+data.hex())
            nonce_card = res[:32]
            secrets_hash = res[32:36]
            recv_hmac = res[36:68]
            secret_with_nonces = hashlib.sha256(shared_secret+nonce_host+nonce_card).digest()
            self.host_aes_key = hashlib.sha256(b'host_aes'+secret_with_nonces).digest()
            self.card_aes_key = hashlib.sha256(b'card_aes'+secret_with_nonces).digest()
            self.host_mac_key = hashlib.sha256(b'host_mac'+secret_with_nonces).digest()
            self.card_mac_key = hashlib.sha256(b'card_mac'+secret_with_nonces).digest()
            shared_hash = hashlib.sha256(secret_with_nonces).digest()[:4]
            if shared_hash != secrets_hash:
                print("Wrong hash of secrets: %s - %s" % (shared_hash.hex(), secrets_hash.hex()))
            h = hmac.new(self.card_mac_key, digestmod='sha256')
            h.update(res[:36])
            expected_hmac = h.digest()
            if expected_hmac != recv_hmac:
                raise RuntimeError("Wrong HMAC. Got %s, expected %s"%(recv_hmac.hex(),expected_hmac.hex()))
            sig = secp256k1.ecdsa_signature_parse_der(res[68:])
            # in case card doesn't follow low s rule (but it should)
            sig = secp256k1.ecdsa_signature_normalize(sig)
            if not secp256k1.ecdsa_verify(sig, hashlib.sha256(res[:68]).digest(), self.card_pubkey):
                raise RuntimeError("Signature is invalid")
        # reset iv
        self.iv = 0
        self.is_secure_channel_open = True
    
    def encrypt(self, data):
        # add padding
        d = data+b'\x80'
        if len(d)%16 != 0:
            d += b'\x00'*(16 - (len(d)%16))
        iv = self.iv.to_bytes(16, 'big')
        backend = default_backend()
        cipher = Cipher(algorithms.AES(self.host_aes_key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        ct = encryptor.update(d)+encryptor.finalize()
        h = hmac.new(self.host_mac_key, digestmod='sha256')
        h.update(iv)
        h.update(ct)
        hmac_len = 31 if len(ct)+32 == 256 else 32
        ct += h.digest()[:hmac_len]
        return ct
    
    def decrypt(self, ct):
        hmac_len = 31 if len(ct)==255 else 32
        recv_hmac = ct[-hmac_len:]
        ct = ct[:-hmac_len]
        iv = self.iv.to_bytes(16, 'big')
        h = hmac.new(self.card_mac_key, digestmod='sha256')
        h.update(iv)
        h.update(ct)
        expected_hmac = h.digest()
        if expected_hmac[:hmac_len] != recv_hmac:
            raise RuntimeError("Wrong HMAC. Got %s, expected %s"%(recv_hmac.hex(),expected_hmac.hex()))
        backend = default_backend()
        cipher = Cipher(algorithms.AES(self.card_aes_key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        # check and remove \x80... padding
        plain = decryptor.update(ct)+decryptor.finalize()
        arr = plain.split(b"\x80")
        if len(arr)==1 or len(arr[-1].replace(b'\x00',b''))>0:
            raise RuntimeError("Wrong padding")
        return (b"\x80".join(arr[:-1]))
    
    def secure_request(self, data):
        # if counter reached maximum - reestablish channel
        if self.iv >= 2**16:
            self.establish_secure_channel()
        ct = self.encrypt(data)
        res = self.request("B0B50000"+(bytes([len(ct)])+ct).hex())
        plaintext = self.decrypt(res)
        self.iv += 1
        if plaintext[:2] == b'\x90\x00':
            return plaintext[2:]
        else:
            raise RuntimeError("Card returned secure error with code %r and data %r" % (plaintext[:2].hex(), plaintext[2:]))

    def close_secure_channel(self):
        self.request("B0B6000000")

    def echo(self, data):
        return self.secure_request(b'\x00\x00'+data)

    def get_random_sc(self):
        return self.secure_request(b'\x01\x00')
