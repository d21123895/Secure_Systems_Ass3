from Blockchain.Backend.util.util import int_to_little_endian, encode_variant, read_variant, little_endian_to_int
from Blockchain.Backend.core.EllepticCurve.op import OP_CODE_FUNCTION
class Script:
    def __init__(self, cmds = None):
        if cmds is None:
            self.cmds = []
        else:
            self.cmds = cmds

    def evaluate(self, z):
        cmds = self.cmds[:]
        stack = []

        while len(cmds) > 0:
            cmd = cmds.pop(0)

            if type(cmd) == int:
                operation = OP_CODE_FUNCTION[cmd]
                if cmd == 172:
                    if not operation(stack, z):
                        print(f"Error in Signature Verification")
                        return False
                    if not operation(stack):
                        print(f"Error in Signature Verification")
                        return False
            
            else:
                stack.append(cmd)
        return True


    #Takes Hash160 and returns the p2pkh ScriptPubKey
    @classmethod
    def p2pkh_script(cls, h160):
        return Script([0x76, 0xa9, h160, 0x88, 0xac])
    
    def __add__(self, other):
        return Script(self.cmds + other.cmds)
    
    def serialise(self):
        #Initialise what is sent
        result = b''
        #Loop through the commands
        for cmd in self.cmds:
            #If Command is an integer it's an opcode
            if type(cmd) == int:
                #Turn the command into a single byte integer
                result += int_to_little_endian(cmd, 1)
            else:
                #Or this is an element and the length needs to be gotten in bytes
                length = len(cmd)
                #Use Pushdata opcode for large lengths
                if length < 75:
                    result += int_to_little_endian(length, 1)
                elif length > 75 and length < 0x100:
                    #76 is pushdata 1
                    result += int_to_little_endian(76, 1)
                    result += int_to_little_endian(length, 1)
                elif length >= 0x100 and length <= 520:
                    #77 is pushdata 2
                    result += int_to_little_endian(77, 1)
                    result += int_to_little_endian(length, 2)
                else:
                    raise ValueError("Command is too long")

                result += cmd
                #Get the length of the whole command
                total = len(result)
                #Encode the length and prepend
                return encode_variant(total) + result

    @classmethod
    def parse(cls, s):
        #Get the length of the entire field
        length = read_variant(s)
        #Initialise the commands array
        cmds = []
        #Initialize the number of bytes we've read to 0
        count = 0
        #Loop until we've read length bytes
        while count < length:
            #Get the current byte
            current = s.read(1)
            #Increment the bytes read
            count += 1
            #Convert the current byte to an integer
            current_byte = current[0]
            #If the current byte is between 1 and 75 inclusive
            if current_byte >= 1 and current_byte <= 75:
                #We have a command set n to be the current byte
                n = current_byte
                #Add the next n bytes as a command
                cmds.append(s.read(n))
                #Increase the count by n
                count += n
            elif current_byte == 76:
                #Op_pushdata1
                data_length = little_endian_to_int(s.read(1))
                cmds.append(s.read(data_length))
                count += data_length + 1
            elif current_byte == 77:
                #Op_pushdata2
                data_length = little_endian_to_int(s.read(2))
                cmds.append(s.read(data_length))
                count += data_length + 2
            else:
                #We have an opcode. set the current byte to op_code
                op_code = current_byte
                #Add the op_code to the list of commands
                cmds.append(op_code)
        if count != length:
            raise SyntaxError('parsing script failed')
        return cls(cmds)
