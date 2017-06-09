import idautils
import idaapi

# search for BC:Login
PAYLOAD_STORE_ADDR = idc.LocByName("StorePayloadLengthW")

def getOperandText(address):
    ops = idaapi.ua_outop2(address, 0)
    return idaapi.tag_remove(ops)

def getName(address):
    op = getOperandText(address).replace("offset ","")
    dAddr = LocByName(op)
    bytesToRead = idc.NextHead(dAddr) - dAddr
    return idaapi.get_ascii_contents(dAddr, bytesToRead, 0)

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

    # get the payload size
    sizeAddr = idc.PrevHead(opAddr)
    sizeRaw = getOperandText(sizeAddr)
    if sizeRaw[-1] == "h":
        sizeRaw = sizeRaw[:-1]
    size = int(sizeRaw, 16)

    print "public const int {} = {}; // Size: {}".format(name, opcode, size)
