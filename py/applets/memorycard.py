from .teapot import Teapot

# embit library: https://github.com/diybitcoinhardware/embit
# works with python3 and micropython
from embit.ec import PrivateKey, PublicKey, secp256k1, Signature

import os, hashlib, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class MemoryCard(Teapot):
    def __init__(self, connection=None):
        super().__init__(connection)
        self.AID = "B00B5111CB01"
        self.iv = 0
        self.card_pubkey = None
        self.card_key = None
        self.host_key = None
        self.mode = "es"
        self.is_secure_channel_open = False

    def get_random(self):
        if self.is_secure_channel_open:
            return self.get_random_sc()
        else:
            return self.request("B0B10000")
    
    def get_random_sc(self):
        return self.request("B0B10000")
    
    def get_card_pubkey(self):
        sec = self.request("B0B2000000")
        self.card_pubkey = PublicKey.parse(sec)
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
        host_prv = PrivateKey(secret)
        host_pub = host_prv.get_public_key()
        host_pub.compressed = False
        data = bytes([65])+host_pub.sec()
        # ee mode - ask card to create ephimerial key and send it to us
        if mode=="ee":
            # get ephimerial pubkey from the card
            res = self.request("B0B40000"+data.hex())
            pub = PublicKey.parse(res[:65])
            secp256k1.ec_pubkey_tweak_mul(pub._point, secret)
            shared_secret = pub.sec()[1:33]
            self.host_key = hashlib.sha256(b'host'+shared_secret).digest()
            self.card_key = hashlib.sha256(b'card'+shared_secret).digest()
            shared_hash = hashlib.sha256(self.host_key+self.card_key).digest()
            recv_hmac = res[65:97]
            h = hmac.new(self.card_key, digestmod='sha256')
            h.update(res[:65])
            expected_hmac = h.digest()
            if expected_hmac != recv_hmac:
                raise RuntimeError("Wrong HMAC. Got %s, expected %s"%(recv_hmac.hex(),expected_hmac.hex()))
            sig = Signature.parse(res[97:])
            # card doesn't follow low s rule, so we need to normalize
            sig._sig = secp256k1.ecdsa_signature_normalize(sig._sig)
            if not self.card_pubkey.verify(sig, hashlib.sha256(res[:97]).digest()):
                raise RuntimeError("Signature is invalid: %r", res[97:].hex())
        # se mode - use our ephimerial key with card's static key
        else:
            pub = PublicKey.parse(self.card_pubkey.sec())
            secp256k1.ec_pubkey_tweak_mul(pub._point, secret)
            shared_secret = pub.sec()[1:33]
            self.host_key = hashlib.sha256(b'host'+shared_secret).digest()
            self.card_key = hashlib.sha256(b'card'+shared_secret).digest()
            shared_hash = hashlib.sha256(self.host_key+self.card_key).digest()
            res = self.request("B0B30000"+data.hex())
            recv_hmac = res[32:64]
            h = hmac.new(self.card_key, digestmod='sha256')
            h.update(res[:32])
            expected_hmac = h.digest()
            if expected_hmac != recv_hmac:
                raise RuntimeError("Wrong HMAC. Got %s, expected %s"%(recv_hmac.hex(),expected_hmac.hex()))
            sig = Signature.parse(res[64:])
            # card doesn't follow low s rule, so we need to normalize
            sig._sig = secp256k1.ecdsa_signature_normalize(sig._sig)
            if not self.card_pubkey.verify(sig, hashlib.sha256(res[:64]).digest()):
                raise RuntimeError("Signature is invalid")
            if res[:32] != shared_hash:
                raise RuntimeError("Meh... Something didn't work? Card returned %s, we have %s" % (res[:32].hex(), shared_hash.hex()))
        # reset iv
        self.iv = 0
        is_secure_channel_open = True
    
    def encrypt(self, data):
        # add padding
        d = data+b'\x80'
        if len(d)%16 != 0:
            d += b'\x00'*(16 - (len(d)%16))
        iv = self.iv.to_bytes(16, 'big')
        backend = default_backend()
        cipher = Cipher(algorithms.AES(self.host_key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        ct = encryptor.update(d)+encryptor.finalize()
        h = hmac.new(self.host_key, digestmod='sha256')
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
        h = hmac.new(self.card_key, digestmod='sha256')
        h.update(iv)
        h.update(ct)
        expected_hmac = h.digest()
        if expected_hmac[:hmac_len] != recv_hmac:
            raise RuntimeError("Wrong HMAC. Got %s, expected %s"%(recv_hmac.hex(),expected_hmac.hex()))
        backend = default_backend()
        cipher = Cipher(algorithms.AES(self.card_key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        # check and remove \x80... padding
        plain = decryptor.update(ct)+decryptor.finalize()
        arr = plain.split(b"\x80")
        if len(arr)==1 or len(arr[-1].replace(b'\x00',b''))>0:
            raise RuntimeError("Wrong padding")
        return (b"".join(arr[:-1]))
    
    def secure_request(self, data):
        # if counter reached maximum - reestablish channel
        if self.iv >= 2**16:
            self.establish_secure_channel()
        ct = self.encrypt(data)
        res = self.request("B0B50000"+(bytes([len(ct)])+ct).hex())
        plaintext = self.decrypt(res)
        self.iv += 1
        return plaintext