import idautils
import idaapi
import re

# search for BC:Login
PAYLOAD_STORE_ADDR = idc.LocByName("StorePayloadLengthW")

def getOperandText(address):
    ops = idaapi.print_operand(address, 0)
    return idaapi.tag_remove(ops)

def getName(address):
    op = getOperandText(address).replace("offset ","")
    dAddr = LocByName(op)
    bytesToRead = idc.NextHead(dAddr) - dAddr
    return idaapi.get_ascii_contents(dAddr, bytesToRead, 0)

opList = []

for xref in XrefsTo(PAYLOAD_STORE_ADDR, 0):
    # get the opcode name from rdata
    nameAddr = idc.NextHead(xref.frm)
    name = getName(nameAddr)

    # get the opcode itself
    opAddr = idc.PrevHead(xref.frm)
    opRaw = getOperandText(opAddr)
    if opRaw[-1] == "h":
        opRaw = opRaw[:-1]
    if len(opRaw) == 1:
        opRaw = "0" + opRaw
    opcode = "0x" + opRaw
    opInt = str(int(opRaw, 16)).zfill(4)

    # get the payload size
    sizeAddr = idc.PrevHead(opAddr)
    sizeRaw = getOperandText(sizeAddr)
    if sizeRaw[-1] == "h":
        sizeRaw = sizeRaw[:-1]
    size = int(sizeRaw, 16)

    # add to list
    #opList.append("{} _sizes[Op.{}] = {};".format(opInt, name, size))
    opList.append("{} public const int {} = {}; // Size: {}".format(opInt, name, opcode, size))

opList.sort();
for i in opList:
    print(re.sub('\d{4}\s','',i))
