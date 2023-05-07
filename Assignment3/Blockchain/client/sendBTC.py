from Blockchain.Backend.util.util import decode_base58
from Blockchain.Backend.core.Script import Script
from Blockchain.Backend.core.Transaction import TxIn, TxOut, Tx
from Blockchain.Backend.core.database.database import AccountDB
from Blockchain.Backend.core.EllepticCurve.EllepticCurve import PrivateKey
import time
import random

class SendBTC:
    def __init__(self, fromAccount, toAccount, Amount, UTXOS):
        self.coin = 100000000
        self.FromPublicAddress = fromAccount
        self.toAccount = toAccount
        self.Amount = Amount * self.coin
        self.utxos = UTXOS

    def script_public_key(self, PublicAddress):
        h160 = decode_base58(PublicAddress)
        script_public_key = Script().p2pkh_script(h160)
        return script_public_key

    def getPrivateKey(self):
        AllAccounts = AccountDB().read()
        for account in AllAccounts:
            if account['PublicAddress'] == self.FromPublicAddress:
                return account['privateKey']

    def prepareTxIn(self):
        TxIns = []
        self.Total = 0
        #Convert Public Address into Public Hash to find outputs that are locked to this hash
        self.From_address_script_pubkey = self.script_public_key(self.FromPublicAddress)
        self.from_public_key_hash = self.From_address_script_pubkey.cmds[2]

        newutxos = {}

        try:
            while len(newutxos < 1):
                newutxos = dict(self.utxos)
                time.sleep(2)
        except Exception as e:
            print(f"Error in converting the Managed Dictionary to Normal Dictionary")

        for TxByte in newutxos:
            if index > random.randint(1, 30):
                if self.total < self.Amount:
                    TxObj = newutxos[TxByte]
                    for index, TxOut in enumerate(TxObj.tx_outs):
                        if TxOut.script_public_key.cmds[2] == self.from_public_key_hash:
                            self.Total += TxOut.Amount
                            prev_tx = bytes.fromhex(TxObj.id())
                            TxIns.append(TxIn(prev_tx, index))
                else:
                    break
        self.isBalanceSufficient = True
        if self.Total < self.Amount:
            self.isBalanceSufficient = False
        return TxIns

    def prepareTxOut(self):
        TxOuts = []
        to_script_public_key = self.script_public_key(self.toAccount)
        TxOuts.append(TxOut(self.Amount, to_script_public_key))

        #Calculate the fee
        self.fee = self.coin
        self.changeAmount = self.Total - self.Amount - self.fee

        TxOuts.append(TxOut(self.changeAmount, self.From_address_script_pubkey))
        return TxOuts
    
    def signTx(self):
        secret = self.getPrivateKey()
        priv = PrivateKey(secret = secret)

        for index, input in enumerate(self.TxIns):
            self.TxObj.sign_input(index, priv, self.From_address_script_pubkey)

        return True

    def prepareTransaction(self):
        self.TxIns = self.prepareTxIn()
        if self.isBalanceSufficient:
            self.TxOuts = self.prepareTxOut()
            self.TxObj = Tx(1, self.TxIns, self.TxOuts, 0)
            self.TxObj.TxId = self.TxObj.id()
            self.signTx()
            return self.TxObj
        return False
        