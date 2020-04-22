'''
looks for opcodes to use as a vtable for c++ heap overwrites
printed value is pointer to desired vtable
'''

__VERSION__ = '0.1'

import immlib
import binascii

#TODO: add support flag to not check in aslr (dll characteristic 0x40) compiled dll's
#TODO: clean up code and variable names
#TODO: comment some crap

imm = immlib.Debugger()

def usage():
    imm.Log("Usage: ")
    imm.Log("!mkvtable [PTR] [Register] [Options]")
    imm.Log("    PTR - Used to signal the number of pointers to pointers for the vtable, can have a +/- offset")
    imm.Log("    Register - Execution will be directed here")
    imm.Log("")
    imm.Log(" [Options]")
    imm.Log("    -db   - Ignore modules compiled with the dynamic base flag")
    imm.Log("    -F[n] - Fuzzy searching enabled, will search for vtable -/+ (n) addresses of control register")
    imm.Log("")
    imm.Log("Example:")
    imm.Log("!mkvtable ptr+4 ptr eax ecx -f3 -db")
    imm.Log("")

def toHexFlip(address):
#    imm.Log("toHex address: %s" % (address))
    b4 = address[0:2]
    b3 = address[2:4]
    b2 = address[4:6]
    b1 = address[6:]
#    imm.Log("b4: %s, b3: %s, b2: %s, b1: %s" % (b4, b3, b2, b1))
    binaddress = chr(int(b1, 16) & 0xff)
    binaddress += chr(int(b2, 16) & 0xff)
    binaddress += chr(int(b3, 16) & 0xff)
    binaddress += chr(int(b4, 16) & 0xff)
#    imm.Log("binaddress len: %d" % len(binaddress))
#    imm.Log("binaddress: %02x, %02x, %02x, %02x" % (ord(binaddress[0]), ord(binaddress[1]), ord(binaddress[2]), ord(binaddress[3])))
    return binaddress

def findPtr2(address):
    binAddress = toHexFlip(address)
    add2 = imm.Search(binAddress)
    return add2

def findPtr(address, offset, sign):
    temp = []
    for add in address:
        if sign == 0:
            ptr = "%08x" % (add)
        if sign == 1:
            ptr = "%08x" % (add - offset)
        if sign == -1:
            ptr = "%08x" % (add + offset)
#        imm.Log("in findPtr add: %08x, offset: %08x, ptr: %s" % (add, offset, ptr))
        add2 = findPtr2(ptr)
        for ad in add2:
#            imm.Log("pointer to address %08x" % ad)
            temp.append(ad)
    return temp

def startSearch(opcodes, fuzzy, args, db):
    address = []
    for op in opcodes:
        address += imm.Search(op)
        for add in address:
            add = int(add)
            page = imm.getMemoryPagebyAddress(add)
##            if db > 0: #dynamic base ignore code 
##                module = imm.getModulebyAddress(add)
##                base = module.baseaddress
##                while(module.baseaddress < module.baseaddress + 2000):
##                        temp = "PE"
##                        data = imm.readString(base)
##                        print "data read: ", data
##                        if data == temp:
##                                print "match at address %08x" % base
##                                characteristic = imm.readShort(base + 0x5e)
##                                print "characteristic: %02x" % characteristic
##                                break
##                        base = base + 1
            access = page.getAccess(human = True)
            if access.find("EXECUTE") == -1:
                address.remove(add)
                continue
#    imm.Log("fuzzy in startSearch value: %d" % fuzzy)
    if fuzzy > 0:
        imm.Log("Fuzzy searching enabled")
        imm.Log("num of addresses before fuzzy: %d" % len(address))
        temp = []
        for ad in address:
            for i in range(0, (fuzzy)):
                temp.append(ad + i)
            for i in range(0, (fuzzy)):
                temp.append(ad - i)
        address = temp
        imm.Log("number of address after fuzzy: %d" % len(address))

    arglen = len(args)-1
    while (arglen > -1):
        if args[arglen].lower().find("ptr+") > -1:
#            imm.Log("found ptr+ arg")
            temp = args[arglen]
            temp = temp.replace("ptr+", "")
            offset = int(temp, 16)
            imm.Log("offset: %08x" % offset)
            sign = 1
            address = findPtr(address, offset, sign)
            arglen = arglen - 1
            continue
        if args[arglen].lower().find("ptr-") > -1:
#            imm.Log("found ptr- arg")
            temp = args[arglen]
            temp = temp.replace("ptr-", "")
            offset = int(temp, 16)
            sign = -1
            address = findPtr(address, offset, sign)
            arglen = arglen - 1
            continue            
        if args[arglen].lower().find("ptr") > -1:
#            imm.Log("found ptr arg")
            offset = 0
            sign = 0
            address = findPtr(address, offset, sign)
            arglen = arglen - 1
            continue
        arglen = arglen - 1
    display(address)
    
def display(address):
    for ad in address:
        imm.Log("Found matching vtable at address: %08x" % ad)  

def main(args):
    if len(args) < 1:
        usage()
        return "Need Arguments"
    arglen = len(args)-1
    eax = 0
    ebx = 0
    ecx = 0
    edx = 0
    edi = 0
    esi = 0
    ebp = 0
    esp = 0
    fuzzy = 0
    db = 0
    
    while(arglen > 0):
        if args[arglen].lower() == "eax":
            eax = 1
        if args[arglen].lower() == "ebx":
            ebx = 1
        if args[arglen].lower() == "ecx":
            ecx = 1
        if args[arglen].lower() == "edx":
            edx = 1
        if args[arglen].lower() == "esi":
            esi = 1
        if args[arglen].lower() == "edi":
            edi = 1
        if args[arglen].lower() == "esp":
            esp = 1
        if args[arglen].lower() == "ebp":
            ebp = 1
        if args[arglen].lower().find("-f") > -1:
            temp = args[arglen].lower()
            temp = temp.replace("-f", "")
            fuzzy = int(temp)
            imm.Log("fuzzy value: %d" % fuzzy)
        if args[arglen].lower().find("-db") > -1:
            db = 1
        arglen = arglen - 1
        
    if eax > 0:
        opcodes = ["\xFF\xE0", "\xFF\xD0", "\x50\xC3"] #JMP CALL PUSH RET
        startSearch(opcodes, fuzzy, args, db)
        imm.Log("EAX search complete")
            
    if ebx > 0:
        opcodes = ["\xFF\xE3", "\xFF\xD3", "\x53\xC3"] #JMP CALL PUSH RET
        startSearch(opcodes, fuzzy, args, db)
        imm.Log("EBX search complete")
        
    if ecx > 0:
        opcodes = ["\xFF\xE1", "\xFF\xD1", "\x51\xC3"] #JMP CALL PUSH RET
        startSearch(opcodes, fuzzy, args, db)
        imm.Log("ECX search complete")

    if edx > 0:
        opcodes = ["\xFF\xE2", "\xFF\xD2", "\x52\xC3"] #JMP CALL PUSH RET
        startSearch(opcodes, fuzzy, args, db)
        imm.Log("EDX search complete")

    if esi > 0:
        opcodes = ["\xFF\xE6", "\xFF\xD6", "\x56\xC3"] #JMP CALL PUSH RET
        startSearch(opcodes, fuzzy, args, db)
        imm.Log("ESI search complete")
        
    if edi > 0:
        opcodes = ["\xFF\xE7", "\xFF\xD7", "\x57\xC3"] #JMP CALL PUSH RET
        startSearch(opcodes, fuzzy, args, db)
        imm.Log("EDI search complete")

    if esp > 0:
        opcodes = ["\xFF\xE4", "\xFF\xD4", "\x54\xC3"] #JMP CALL PUSH RET
        startSearch(opcodes, fuzzy, args, db)
        imm.Log("ESP search complete")

    if ebp > 0:
        opcodes = ["\xFF\xE5", "\xFF\xD5", "\x55\xC3"] #JMP CALL PUSH RET
        startSearch(opcodes, fuzzy, args, db)
        imm.Log("EBP search complete")

    return "Search Complete"

