from Blockchain.Backend.core.Script import Script
from Blockchain.Backend.util.util import read_variant, int_to_little_endian, bytes_needed, decode_base58, little_endian_to_int, encode_variant, hash256

ZERO_HASH = b'\0' * 32
Reward = 50

Private_Key = '101035208882034877515009941886420237635219087872848967868560395777618548562857'
Miner_Address = '17YvSjdftGwKe4J22TibAnOKDZNu6Z8t43'
SignHash_All = 1

class CoinbaseTx:
    def __init__(self, BlockHeight):
        self.BlockHeightInLittleEndian = int_to_little_endian(BlockHeight, bytes_needed(BlockHeight))

    def CoinbaseTransaction(self):
        prev_tx = ZERO_HASH
        prev_index = 0xffffffff

        tx_ins = []
        tx_ins.append(TxIn(prev_tx, prev_index))
        tx_ins[0].script_sig.cmds.append(self.BlockHeightInLittleEndian)

        tx_outs = []
        target_amount = Reward * 100000000
        target_h160 = decode_base58(Miner_Address)
        target_script = Script.p2pkh_script(target_h160)
        tx_outs.append(TxOut(amount = target_amount, script_public_key = target_script))
        coinBaseTx = Tx(1, tx_ins, tx_outs, 0)
        coinBaseTx.TxId = coinBaseTx.id()
        return coinBaseTx

class Tx:
    command = b'Tx'
    def __init__(self, version, tx_ins, tx_outs, locktime):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime

    def id(self):
        return self.hash().hex()
    
    #Binary hash of serialisation
    def hash(self):
        return hash256(self.serialise())[::-1]
    
    #Takes byte stream and parses the transaction to return a Tx Object
    def parse(cls, s):
        version = little_endian_to_int(s.read(4))
        num_inputs = read_variant(s)
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(s))
        num_outputs = read_variant(s)
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(s))
        locktime = little_endian_to_int(s.read(4))
        return cls(version, inputs, outputs, locktime)

    def serialise(self):
        result = int_to_little_endian(self.version, 4)
        result += encode_variant(len(self.tx_ins))

        for tx_in in self.tx_ins:
            result += tx_in.serialise()

        result += encode_variant(len(self.tx_outs))
        for tx_out in self.tx_outs:
            result += tx_out.serialise()

        result += int_to_little_endian(self.locktime, 4)
        return result
    
    def sign_hash(self, input_index, script_public_key):
        s = int_to_little_endian(self.version, 4)
        s += encode_variant(len(self.tx_ins))

        for i, tx_in in enumerate(self.tx_ins):
            if i == input_index:
                s += TxIn(tx_in.prev_tx, tx_in.prev_index, script_public_key).serialise()
            else:
                s += TxIn(tx_in.prev_tx, tx_in.prev_index).serialise()

        s += encode_variant(len(self.tx_outs))
        for tx_out in self.tx_outs:
            s += tx_out.serialise()

        s += int_to_little_endian(self.locktime, 4)
        s += int_to_little_endian(SignHash_All, 4)
        h256 = hash256(s)
        return int.from_bytes(h256, 'big')

    def sign_input(self, input_index, private_key, script_public_key):
        z = self.sign_hash(input_index, script_public_key)
        der = private_key.sign(z).der()
        sig = der + SignHash_All.to_bytes(1, 'big')
        sec = private_key.point.sec()
        self.tx_ins[input_index].script_sig = Script([sig, sec])

    def verify_input(self, input_index, script_public_key):
        tx_in = self.tx_ins[input_index]
        z = self.sign_hash(input_index, script_public_key)
        combined = tx_in.script_sig + script_public_key
        return combined.evaluate(z)

    #Checks there is 1 input and check if prev_tx is b'\x00' * 32 and prev_index is 0xfffffff
    def is_coinbase(self):
        if len(self.tx_ins) != 1:
            return False
        first_input = self.tx_ins[0]
        if first_input.prev_tx != b'\x00' * 32:
            return False
        if first_input.prev_index != 0xffffffff:
            return False
        return True

    @classmethod
    def to_obj(cls, item):
        TxInList = []
        TxOutList = []
        cmds = []

        #Convert Transaction Input to the object
        for tx_in in item['tx_ins']:
            for cmd in tx_in['script_sig']['cmds']:
               
                if tx_in['prev_tx'] == "0000000000000000000000000000000000000000000000000000000000000000":
                    cmds.append(int_to_little_endian(int(cmd), bytes_needed(int(cmd))))
                else:
                    if type(cmd) == int:
                        cmds.append(cmd)
                    else:
                        cmds.append(bytes.fromhex(cmd))
            TxInList.append(TxIn(bytes.fromhex(tx_in['prev_tx']),tx_in['prev_index'],Script(cmds)))   

        
        #Convert Transaction output to Object
        cmdsout = []
        for tx_out in item['tx_outs']:
            for cmd in tx_out['script_public_key']['cmds']:
                if type(cmd) == int:
                    cmdsout.append(cmd)
                else:
                    cmdsout.append(bytes.fromhex(cmd))
                    
            TxOutList.append(TxOut(tx_out['amount'],Script(cmdsout)))
            cmdsout= []
        
        return cls(1, TxInList, TxOutList, 0)

#Convert Transactions
    def to_dict(self):
        for tx_index, tx_in in enumerate(self.tx_ins):
            if self.is_coinbase():
                tx_in.script_sig.cmds[0] = little_endian_to_int(tx_in.script_sig.cmds[0])

            tx_in.prev_tx = tx_in.prev_tx.hex()
            for index, cmd in enumerate(tx_in.script_sig.cmds):
                if isinstance(cmd, bytes):
                    tx_in.script_sig.cmds[index] = cmd.hex()
            tx_in.script_sig = tx_in.script_sig.__dict__
            self.tx_ins[tx_index] = tx_in.__dict__

        for index, tx_out in enumerate(self.tx_outs):
            tx_out.script_public_key.cmds[2] = tx_out.script_public_key.cmds[2].hex()
            tx_out.script_public_key = tx_out.script_public_key.__dict__
            self.tx_outs[index] = tx_out.__dict__

        return self.__dict__

class TxIn:
    def __init__(self, prev_tx, prev_index, script_sig = None, sequence = 0xffffffff):
        self.prev_tx = prev_tx
        self.prev_index = prev_index
        self.sequence = sequence
        if script_sig is None:
            self.script_sig = Script()
        else:
            self.script_sig = script_sig

    def serialise(self):
        result = self.prev_tx[::-1]
        result += int_to_little_endian(self.prev_index, 4)
        result += self.script_sig.serialise()
        result += int_to_little_endian(self.sequence, 4)
        return result
    
    @classmethod
    def parse(cls, s):
        prev_tx = s.read(32)[::-1]
        prev_index = little_endian_to_int(s.read(4))
        script_sig = Script.parse(s)
        sequence = little_endian_to_int(s.read(4))
        return cls(prev_tx, prev_index, script_sig, sequence)

class TxOut:
    def __init__(self, amount, script_public_key):
        self.amount = amount
        self.script_public_key = script_public_key

    def serialise(self):
        result = int_to_little_endian(self.amount, 8)
        result += self.script_public_key.serialise()
        return result

    @classmethod
    def parse(cls,s):
        amount = little_endian_to_int(s.read(8))
        script_public_key = Script.parse(s)
        return cls(amount, script_public_key)


