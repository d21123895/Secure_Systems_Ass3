import sys
sys.path.append('/Users/Thomas Duffy/OneDrive - Technological University Dublin/Documents/Secure Systems Development/Assignment3')
from Blockchain.Backend.core.EllepticCurve.EllepticCurve import Sha256Point
import secrets
from Blockchain.Backend.util.util import hash160, hash256
from Blockchain.Backend.core.database.database import AccountDB

class account:
    def createKeys(self):
        Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

        G = Sha256Point(Gx, Gy)

        #Create Private Key
        self.privateKey = secrets.randbits(256)
        
        unCompressedPublicKey = self.privateKey * G
        Xpoint = unCompressedPublicKey.x
        Ypoint = unCompressedPublicKey.y

        if Ypoint.num % 2 == 0:
            compressedKey = b'\x02' + Xpoint.num.to_bytes(32, 'big')
        else:
            compressedKey = b'\x03' + Xpoint.num.to_bytes(32, 'big')

        hsh160 = hash160(compressedKey)
        #Prefix for Mainnet
        main_prefix = b'\x00'

        newAddr = main_prefix + hsh160

        #Checksum
        checksum = hash256(newAddr)[:4]
        newAddr = newAddr + checksum
        BASE58_ALPHABET = '123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

        count = 0 

        for c in newAddr:
            if c == 0:
                count += 1
            else:
                break
        
        num = int.from_bytes(newAddr, 'big')
        prefix = '1' * count

        result = ''

        while num > 0:
            num , mod = divmod(num, 58)
            result = BASE58_ALPHABET[mod] + result

        self.PublicAddress = prefix + result

        print(f"Private Key {self.privateKey}")
        print(f"Public Address {self.PublicAddress}")



if __name__ == "__main__":
    acct = account()
    acct.createKeys()
    AccountDB().write([acct.__dict__])
