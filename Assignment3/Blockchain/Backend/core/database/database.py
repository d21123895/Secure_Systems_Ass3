import os
import json

class BaseDB:
    def __init__(self):
        self.basepath = 'data'
        self.filepath = '/'.join((self.basepath, self.filename))
#Read from file
    def read(self):
        if not os.path.exists(self.filepath):
            print(f"File {self.filepath} not available")
            return False
        
        with open(self.filepath, 'r') as file:
            raw = file.readline()

        if len(raw) > 0:
            data = json.loads(raw)
        else:
            data = []
        return data
    
#Update file
    def update(self, data):
        with open(self.filepath, 'w+') as f:
            f.write(json.dumps(data))
        return True
    
#Write to file
    def write(self, item):
        data = self.read()
        if data:
            data = data + item
        else:
            data = item

        with open(self.filepath, "w+") as file:
            file.write(json.dumps(data))

#Class to store blockchain data in a file
class BlockchainDB(BaseDB):
    def __init__(self):
        self.filename = 'blockchain'
        super().__init__()

    def lastBlock(self):
        data = self.read()
        if data:
            return data[-1]
        
class AccountDB(BaseDB):
    def __init__(self):
        self.filename = 'account'
        super().__init__()

class NodeDB(BaseDB):
    def __init__(self):
        self.filename = 'node'
        super().__init__()