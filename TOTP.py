# Reference: RFC-6283
import binascii
import time
import hmac, hashlib, base64


''' Usage:
    #1. Use a str to initiate.
        totp = TOTP('5FO25YTPWBULEHGX')
        # In this case, the key will first be base32-decoded.

    #2. Use a bytes to initiate.
        totp = TOTP(b'1234567890')
        # In this case, the key will be treated as the secret itself.

    #3. Generate HMAC-SHA1 TOTP Code using current timestamp
        totp.TOTP1()

    #4. Generate HMAC-SHA256 and HMAC-SHA512 TOTP Code using current timestamp
        totp.TOTP256()
        totp.TOTP512()

    #5. Generate HMAC-SHA* TOTP Code using a specific timestamp
        totp.TOTP1_ex(timestamp: int)
        totp.TOTP256_ex(timestamp: int)
        totp.TOTP512_ex(timestamp: int)

    #6. Mannually generate TOTP Code
        totp.Key = **Some key**
        totp.GenerateTOTP(
            self.GetTS_ex(**timestamp**: int),
            **hashlib.sha1 | hashlib.sha256 | hashlib.sha512 | etc.**
        )

    #7. Some utilities
        TOTP.hex2bytes(hex_string: str) -> bytes
        totp.GetTS() -> str
        totp.GetTS_ex(timestamp: int) -> str
'''
class TOTP():

    def __init__(self,
                 key: bytes | str = None,
                 *,
                 codeDigits: int = 6,
                 aliveDuration: int = 30,
                 startTS: int = 0):

        self._key = b''
        self._codeDigits = 0
        self._alive_duration = 1
        self._start_ts = 0

        self.Key = key
        self.CodeDigits = codeDigits
        self.AliveDuration = aliveDuration
        self.StartTS = startTS

    @property
    def Key(self):
        return self._key

    @Key.setter
    def Key(self, v: str):
        if isinstance(v, str):
            self._key = base64.b32decode(v)
        elif isinstance(v, bytes):
            self._key = v
        else:
            try:
                self._key = bytes(v)
            except:
                raise TypeError(f'Cannot convert {v} into a byte array')

    @property
    def CodeDigits(self):
        return self._codeDigits

    @CodeDigits.setter
    def CodeDigits(self, v: int):
        if isinstance(v, int):
            self._codeDigits = 0 if v < 0 else 8 if v > 8 else v

    # Alias of CodeDigits
    @property
    def Digits(self):
        return self.CodeDigits

    @Digits.setter
    def Digits(self, v: int):
        self.CodeDigits = v

    @property
    def AliveDuration(self):
        return self._alive_duration

    @AliveDuration.setter
    def AliveDuration(self, v: int):
        if type(v) != int:
            raise TypeError(f'{v} is not an integer')
        
        self._alive_duration = 1 if v < 1 else v

    # Alias of AliveDuration
    @property
    def TimeStep(self):
        return self.AliveDuration

    @TimeStep.setter
    def TimeStep(self, v: int):
        self.AliveDuration = v

    @property
    def StartTS(self):
        return self._start_ts

    @StartTS.setter
    def StartTS(self, v: int):
        if type(v) != int:
            raise TypeError(f'{v} is not an integer')

        self._start_ts = 0 if v < 0 else v


    # Parameter:
    #   @hex_ : hex str
    # Returns:
    #   <class 'bytes'> : byte array
    # Note:
    #   The binascii.unhexlify method will correctly convert any byte in the str,
    #   so we don't need to add another byte to the beginning of the hex str.
    @classmethod
    def hex2bytes(cls, hex_: str) -> bytes:

        # We don't need the '0x' prefix
        if '0x' == hex_[:2].lower():
            hex_ = hex_[2:]
        
        # Add one byte to get the right conversion (Java implementation)
        # hex_ = '10' + hex_

        # Get byte array
        byte_array = binascii.unhexlify(hex_)

        # Do not return the first byte,
        # it is what we added in the first step of this conversion (Java Implementation)
        # return byte_array[1:]
        return byte_array


    # Parameters:
    #   @crypto : hash method
    #   @content : hmac msg
    # Returns:
    #   <class 'bytes'> : hash byte array
    def hmac_sha(self,
                 crypto: callable,
                 content: bytes) -> bytes:
        hmac_sha_method = hmac.new(self.Key, content, crypto)

        return hmac_sha_method.digest()


    # Parameters:
    #   @ts : timestamp
    #   @crypto : hash method
    # Returns:
    #   <class 'str'> : Time-based One-Time Password (length = codeDigits)
    def GenerateTOTP(self,
                     ts: str,
                     crypto: callable) -> str:
        bMessage = self.hex2bytes(ts)
        bHash    = self.hmac_sha(crypto, bMessage)

        iOffset  = bHash[-1] & 0xf
        iBinary  = ((bHash[iOffset]     & 0x7f) << 24) | \
                   ((bHash[iOffset + 1] & 0xff) << 16) | \
                   ((bHash[iOffset + 2] & 0xff) << 8 ) | \
                   ( bHash[iOffset + 3] & 0xff)

        iOtp     = iBinary % (10 ** self.CodeDigits)
        sResult  = f'{iOtp:0>{self.CodeDigits}}'
        return sResult

    # Returns:
    #   <class 'str'> : timestamp for authentication
    def GetTS(self) -> str:
        # A timestamp is seconds count from 1970/1/1 00:00 UTC,
        # so it doesn't need a conversion.
        cur_ts = int(time.time())
        return self.GetTS_ex(cur_ts)


    # Parameters:
    #   @raw_ts : the specific timestamp
    # Returns:
    #   <class 'str'> : timestamp for authentication
    def GetTS_ex(self, raw_ts: int) -> str:
        raw_ts = 0 if raw_ts < 0 else raw_ts
        ts     = (raw_ts - self.StartTS) // self.AliveDuration

        return f'{hex(ts)[2:].upper():0>16}'
    

    # For 'TOTP.*?' methods:
    #   Returns:
    #     <class 'str'> : Current TOTP
    # For 'TOTP.*?_ex' methods:
    #   Returns:
    #     <class 'str'> : TOTP under specific timestamp
    def TOTP1(self) -> str:
        return self.GenerateTOTP(
            self.GetTS(),
            hashlib.sha1
        )

    def TOTP1_ex(self, ts: int) -> str:
        return self.GenerateTOTP(
            self.GetTS_ex(ts),
            hashlib.sha1
        )

    def TOTP256(self) -> str:
        return self.GenerateTOTP(
            self.GetTS(),
            hashlib.sha256
        )

    def TOTP256_ex(self, ts: int) -> str:
        return self.GenerateTOTP(
            self.GetTS_ex(ts),
            hashlib.sha256
        )

    def TOTP512(self) -> str:
        return self.GenerateTOTP(
            self.GetTS(),
            hashlib.sha512
        )

    def TOTP512_ex(self, ts: int) -> str:
        return self.GenerateTOTP(
            self.GetTS_ex(ts),
            hashlib.sha512
        )

    
