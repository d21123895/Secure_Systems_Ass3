import sys
sys.path.append('/Users/Thomas Duffy/OneDrive - Technological University Dublin/Documents/Secure Systems Development/Assignment3')

from base64 import encode
from io import BytesIO
from Blockchain.Backend.util.util import int_to_little_endian, little_endian_to_int, hash256, encode_variant, read_variant

MAGIC_NUMBER = b'\xf9\xbe\xb4\xd9'
FINISHED_SENDING =b'\x0a\x11\x09\x07'
class NetworkEnvelope:
    def __init__(self, command, payload):
        self.command = command
        self.payload = payload
        self.magic = MAGIC_NUMBER

    @classmethod
    def parse(cls, s):
        magic = s.read(4)

        if magic != MAGIC_NUMBER:
            raise RuntimeError(f"Magic is not right {magic.hex()} vs {MAGIC_NUMBER.hex()}")
        
        command = s.read(12)
        command = command.strip(b'\x00')
        payloadLen = little_endian_to_int(s.read(4))
        checksum = s.read(4)
        payload = s.read(payloadLen)
        calculatedChecksum = hash256(payload)[:4]

        if calculatedChecksum != checksum:
            raise IOError("Checksum does not match")
        
        return cls(command, payload)

    def serialise(self):
        result = self.magic
        result += self.command + b'\x00' * (12 - len(self.command))
        result += int_to_little_endian(len(self.payload), 4)
        result += hash256(self.payload)[:4]
        result += self.payload
        return result 
    
    def stream(self):
        return BytesIO(self.payload)

class requestBlock:
    command = b'requestBlock'

    def __init__(self, startBlock = None, endBlock = None) -> None:
        if startBlock is None:
            raise RuntimeError("Starting Block cannot be None")
        else:
            self.startBlock = startBlock
        
        if endBlock is None:
            self.endBlock = b'\x00' * 32
        else: 
            self.endBlock = endBlock
    
    @classmethod
    def parse(cls, stream):
        startBlock = stream.read(32)
        endBlock = stream.read(32)
        return startBlock, endBlock

    def serialise(self):
        result = self.startBlock
        result += self.endBlock
        return result 

class portlist:
    command = b'portlist'
    def __init__(self, ports = None):
        self.ports = ports

    @classmethod
    def parse(cls, s):
        ports = []
        length = read_variant(s)

        for _ in range(length):
            port = little_endian_to_int(s.read(4))
            ports.append(port)
        
        return ports

    def serialise(self):
        result = encode_variant(len(self.ports))

        for port in self.ports:
            result += int_to_little_endian(port, 4)
        
        return result

class FinishedSending:
    command = b'Finished'

    @classmethod
    def parse(cls, s):
        magic = s.read(4)

        if magic == FINISHED_SENDING:
            return "Finished"

    def serialise(self):
        result = FINISHED_SENDING 
        return result 