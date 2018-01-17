from triton import TritonContext, ARCH, Instruction, MemoryAccess, CPUSIZE, MODE, OPCODE
from triton import TritonContext as T
import lief
import gc
import string
import sys

# debug = 'detailed'
debug = 'no'
pcsymvar =None
Triton = TritonContext()
astc=Triton.getAstContext()
MAX_ARGC = 3
MAX_ARG_SIZE = 64
input ={}
frameDepth = 0;
returnStack = []

def strlenHandler():
    print "In strlen"

def printfHandler():
    print "In printf"

def libcMainHandler():
    print '[+] __libc_start_main hooked'

    # Get arguments
    main = Triton.getConcreteRegisterValue(Triton.registers.rdi)

    # Push the return value to jump into the main() function
    Triton.concretizeRegister(Triton.registers.rsp)
    Triton.setConcreteRegisterValue(Triton.registers.rsp, Triton.getConcreteRegisterValue(Triton.registers.rsp)-CPUSIZE.QWORD)

    ret2main = MemoryAccess(Triton.getConcreteRegisterValue(Triton.registers.rsp), CPUSIZE.QWORD)
    Triton.concretizeMemory(ret2main)
    Triton.setConcreteMemoryValue(ret2main, main)

    # Setup argc / argv
    Triton.concretizeRegister(Triton.registers.rdi)
    Triton.concretizeRegister(Triton.registers.rsi)

    argvs = [
        "sample_1",      # argv[0]
        "my_first_arg",  # argv[1]
    ]

    # Define argc / argv
    base  = 0x20000000
    addrs = list()

    for argv in argvs:
        addrs.append(base)
        Triton.setConcreteMemoryAreaValue(base, argv+'\x00')
        base += len(argv)+1

    argc = len(argvs)
    argv = base
    for addr in addrs:
        Triton.setConcreteMemoryValue(MemoryAccess(base, CPUSIZE.QWORD), addr)
        base += CPUSIZE.QWORD

    Triton.setConcreteRegisterValue(Triton.registers.rdi, argc)
    Triton.setConcreteRegisterValue(Triton.registers.rsi, argv)

    return 0

customRelocation = [
    ('strlen',            strlenHandler,   0x10000000),
    ('printf',            printfHandler,   0x10000001),
    ('__libc_start_main', libcMainHandler, 0x10000002),
]

def hookingHandler():
    pc = Triton.getConcreteRegisterValue(Triton.registers.rip)
    for rel in customRelocation:
        if rel[2] == pc:
            # Emulate the routine and the return value
            ret_value = rel[1]()
            Triton.concretizeRegister(Triton.registers.rax)
            Triton.setConcreteRegisterValue(Triton.registers.rax, ret_value)

            # Get the return address
            ret_addr = Triton.getConcreteMemoryValue(MemoryAccess(Triton.getConcreteRegisterValue(Triton.registers.rsp), CPUSIZE.QWORD))

            # Hijack RIP to skip the call
            Triton.concretizeRegister(Triton.registers.rip)
            Triton.setConcreteRegisterValue(Triton.registers.rip, ret_addr)

            # Restore RSP (simulate the ret)
            Triton.concretizeRegister(Triton.registers.rsp)
            Triton.setConcreteRegisterValue(Triton.registers.rsp, Triton.getConcreteRegisterValue(Triton.registers.rsp)+CPUSIZE.QWORD)
    return

def initilizeInput():
    global input
    for i in range(MAX_ARG_SIZE * MAX_ARGC):
        input[0x90000000+i] = 0

def printStack():
    print "EBP = " + str(format(Triton.getConcreteRegisterValue(Triton.registers.rbp),'x'))
    print "EBP = " + str(format(Triton.getConcreteRegisterValue(Triton.registers.rsp), 'x'))
    ebp = Triton.getConcreteRegisterValue(Triton.registers.rbp)

    for i in range(0,32,4):
        value = Triton.getConcreteMemoryAreaValue(ebp-i,4)
        print str(format(ebp-i, 'x'))+":",
        for  a in value:
         print   "  "+ str(format(ord(a),'x')),
        print ""
def dumpInput():
    for arg in range(MAX_ARGC):
        print "Argument ",arg+1,":",
        for byteptr in range(100):
            c = Triton.getConcreteMemoryAreaValue(0x90000000+arg*100+byteptr,CPUSIZE.BYTE)
            print ord(c[0]),
        print " "

def emulate(pc):
    global frameDepth

    while(True):
        opcode=Triton.getConcreteMemoryAreaValue(pc, 16)
        inst = Instruction()
        inst.setOpcode(opcode)
        inst.setAddress(pc)

        Triton.processing(inst)
        # if(inst.getAddress() == int(sys.argv[2],16)):
        #     dumpInput()
        #     exit(0)
        print inst

        if(inst.getType() == OPCODE.CALL):
            frameDepth += 1
            esp = Triton.getConcreteRegisterValue(Triton.registers.rsp)
            retAddr = Triton.getConcreteMemoryValue(MemoryAccess(esp,4))
            returnStack.append(retAddr)
            for ret in returnStack:
                print format(ret, 'x')

        # printStack()
        if inst.getAddress() == 0x804849b or inst.getAddress() == 0x804847a or inst.getAddress() == 0x804844c:
            print "EAX:"+str(format(Triton.getConcreteRegisterValue(Triton.registers.rax),'x')) + \
                  "    EDX:"+str(format(Triton.getConcreteRegisterValue(Triton.registers.rdx),'x')) + \
                  "    EBP : "+ str(format(Triton.getConcreteRegisterValue(Triton.registers.rbp),'x')) + \
                  "    EIP : "+ str(format(Triton.getConcreteRegisterValue(Triton.registers.rip),'x'))

        id = Triton.getSymbolicRegisterId(Triton.registers.rax)
        currentEBP = Triton.getConcreteRegisterValue(Triton.registers.rbp)


        if(frameDepth == 0 and inst.getType() == OPCODE.RET):
            break

        hookingHandler()

        if inst.getType() == OPCODE.RET:
            frameDepth-=1;
            evaluatepc()
        if (inst.getAddress() == 0):
            exit(0)
        pc = Triton.getConcreteRegisterValue(Triton.registers.rip)



def evaluatepc():
    print
    print

    if debug=='detailed' :
        print Triton.getSymbolicVariables()
        print "In EvaluatePc--EIP =  " + str(format(Triton.getConcreteRegisterValue(Triton.registers.rip),'x'))

    ipid = Triton.getSymbolicRegisterId(Triton.registers.rip)
    ipast = Triton.getAstFromId(ipid)
    print Triton.getSymbolicMemory()

    print "ARGVEXPR = " + str(Triton.getSymbolicMemory()[0x90000000 + 100])
    print "IPEXPR = "  + str( Triton.getSymbolicExpressionFromId(ipid) )
    ipast = astc.equal(ipast, astc.bv(int(sys.argv[3],16),32))
    print "IPAST = " + str(ipast)
    fullast = astc.land([ipast, Triton.getPathConstraintsAst()])

    model = Triton.getModel(ipast).items()

    for k,v in model:
        symVar = Triton.getSymbolicVariableFromId(k)

        # Save the new input as seed.
        print({format(symVar.getKindValue(),'x'): format(v.getValue(),'x')})

    correctReturnAddr = returnStack[len(returnStack) - 1]
    currPc = Triton.getConcreteRegisterValue(Triton.registers.rip);
    if (currPc == correctReturnAddr or currPc == int(sys.argv[3], 16)):
        pass
    else:
        Triton.setConcreteRegisterValue(Triton.registers.rip, returnStack.pop())
    currPc = Triton.getConcreteRegisterValue(Triton.registers.rip);

    if(len(model) >=4):
        print "+++++++++++++done+++++++++++++"
        exit(0)



        # exit(0)
    # a=raw_input()
    print
    print

# def getMemoryString(addr):
#     s = str()
#     index = 0
#
#     while Triton.getConcreteMemoryValue(addr+index):
#         c = chr(Triton.getConcreteMemoryValue(addr+index))
#         if c not in string.printable: c = ""
#         s += c
#         index  += 1
#
#     return s
#
#
# def getFormatString(addr):
#     return getMemoryString(addr)                                                    \
#            .replace("%s", "{}").replace("%d", "{:d}").replace("%#02x", "{:#02x}")   \
#            .replace("%#x", "{:#x}").replace("%x", "{:x}").replace("%02X", "{:02x}") \
#            .replace("%c", "{:c}").replace("%02x", "{:02x}").replace("%ld", "{:d}")  \
#            .replace("%*s", "").replace("%lX", "{:x}").replace("%08x", "{:08x}")     \
#            .replace("%u", "{:d}")
#
# def strlenHandler():
#     print '[+] Strlen hooked'
#
#     # Get arguments
#     arg1 = getMemoryString(Triton.getConcreteRegisterValue(Triton.registers.rdi))
#
#     # Return value
#     return len(arg1)
#
# def printfHandler():
#     print '[+] printf hooked'
#
#     # Get arguments
#     arg1   = getFormatString(Triton.getConcreteRegisterValue(Triton.registers.rdi))
#     arg2   = Triton.getConcreteRegisterValue(Triton.registers.rsi)
#     arg3   = Triton.getConcreteRegisterValue(Triton.registers.rdx)
#     arg4   = Triton.getConcreteRegisterValue(Triton.registers.rcx)
#     arg5   = Triton.getConcreteRegisterValue(Triton.registers.r8)
#     arg6   = Triton.getConcreteRegisterValue(Triton.registers.r9)
#     nbArgs = arg1.count("{")
#     args   = [arg2, arg3, arg4, arg5, arg6][:nbArgs]
#     s      = arg1.format(*args)
#
#     sys.stdout.write(s)
#
#     # Return value
#     return len(s)



def makerelocations(binary):
    for rel in binary.pltgot_relocations:
        symbolName = rel.symbol.name
        symbolRelo = rel.address
        for crel in customRelocation:
            if symbolName == crel[0]:
                print '[+] Hooking %s' %(symbolName)
                Triton.setConcreteMemoryValue(MemoryAccess(symbolRelo,CPUSIZE.DWORD),crel[2])
    return

def loadBinary(path):
    binary  = lief.parse(path)
    phdrs  = binary.segments
    for phdr in phdrs:
        size = phdr.physical_size
        vaddr  = phdr.virtual_address
        print '[+] Loading 0x%06x - 0x%06x' %(vaddr, vaddr+size)
        Triton.setConcreteMemoryAreaValue(vaddr, phdr.content)
    makerelocations(binary)
    return binary


def setEnvironment():

    #set argv pointers
    for i in range(MAX_ARGC):
        Triton.setConcreteMemoryValue(MemoryAccess(0x80000000+i*4,4),0x090000000+i*MAX_ARG_SIZE)
    #convert argv to symbolic arguments
    Triton.setConcreteRegisterValue(Triton.registers.rbp, 0x7fffffff)
    Triton.setConcreteRegisterValue(Triton.registers.rsp, 0x6fffffff)
    Triton.setConcreteMemoryValue(MemoryAccess(0x06ffffffb + 0x0C, 4), 0x80000000)
    Triton.clearPathConstraints()

def setInput(inp):
    global frameDepth
    frameDepth = 0
    global returnStack
    returnStack = []
    Triton.concretizeAllRegister()
    Triton.concretizeAllMemory()
    Triton.convertRegisterToSymbolicVariable(Triton.registers.rip)
    for i in range(MAX_ARGC):
        for j in range(MAX_ARG_SIZE):
            if (0x90000000+i*MAX_ARG_SIZE+j) not in inp:
                Triton.convertMemoryToSymbolicVariable(MemoryAccess(0x90000000 + (i*MAX_ARG_SIZE+j),1), "argv["+str(i)+"]"+"["+str(j)+"]")
    argcSymbolized = False;
    #convert argc to symbolic variable
    for address, value in inp.items():
        # print "Setting ", format(address,'x'), "to ", value
        if address == 0x70000003:
            argcSymbolized = True
            Triton.setConcreteMemoryValue(address, value)
            # Triton.convertMemoryToSymbolicVariable(MemoryAccess(address, 4))

        else:
            Triton.setConcreteMemoryValue(address, value)
            Triton.convertMemoryToSymbolicVariable(MemoryAccess(address, CPUSIZE.BYTE))

    # if not argcSymbolized:
    #     Triton.convertMemoryToSymbolicVariable(MemoryAccess(0x6ffffffb+0x8,4))
    Triton.convertMemoryToSymbolicVariable(MemoryAccess(0x0804a020 + (i * MAX_ARG_SIZE + j), 4))
    Triton.convertMemoryToSymbolicVariable(MemoryAccess(0x0804a024 + (i * MAX_ARG_SIZE + j), 4))

def calculateNewInputs():
    inputs = list()

    # Get path constraints from the last execution
    pco = Triton.getPathConstraints()
    # print pco
    # We start with any input. T (Top)

    previousConstraints = astc.equal(astc.bvtrue(), astc.bvtrue())

    # Go through the path constraints
    for pc in pco:
        # print "PC",pc
        # If there is a condition
        if pc.isMultipleBranches():
            # Get all branches
            branches = pc.getBranchConstraints()
            # print "branches ", branches
            for branch in branches:
                # print "Branch" , branch

                # Get the constraint of the branch which has been not taken
                if branch['isTaken'] == False:
                    # print "Src addr", format(branch['srcAddr'],'x'), "Dst Addr ", format(branch['dstAddr'],'x' )
                    # Ask for a model
                    if(debug=='detailed'):
                        print astc.land([previousConstraints, branch['constraint']])
                    models = Triton.getModel(astc.land([previousConstraints, branch['constraint']]))
                    seed = dict()
                    for k, v in models.items():
                        # Get the symbolic variable assigned to the model
                        if (debug == 'detailed'):
                            print "[+] calculated symbols====>"

                        symVar = Triton.getSymbolicVariableFromId(k)

                        # Save the new input as seed.
                        seed.update({symVar.getKindValue(): v.getValue()})
                        if (debug == 'detailed'):
                            print format(symVar.getKindValue(),'x'), v
                    if seed:
                        inputs.append(seed)
                    if (debug == 'detailed'):print ""

        # Update the previous constraints with true branch to keep a good path.
        if (debug == 'detailed'):
            print "Previous Constraints ",previousConstraints,"\n\n"
        previousConstraints = astc.land([previousConstraints, pc.getTakenPathConstraintAst()])

    # Clear the path constraints to be clean at the next execution.
        Triton.clearPathConstraints()

    return inputs


if __name__ == '__main__':
    # Define the target architecture
    Triton.setArchitecture(ARCH.X86_64)
    # Load the binary


    binary = loadBinary(sys.argv[1])


    # Triton.enableMode(MODE.ALIGNED_MEMORY,True)
    Triton.enableMode(MODE.AST_DICTIONARIES, True)
    Triton.enableTaintEngine(False)

    initilizeInput()
    nextInputs = list()
    previousInputs=list()
    nextInputs.append(input)
    while(len(nextInputs) != 0):
        if (debug == 'detailed'):
            print nextInputs
        inp = nextInputs[0]
        del nextInputs[0]
        if inp not in previousInputs:
            setEnvironment()
            setInput(inp)
            if (debug == 'detailed'):
                print "[+]=====> Starting Emulation with input" + str(inp)
                print "[+]=====> Starting Emulation with " + str(len(inp)) + " inputs"
            emulate(binary.entrypoint)
            newIn = calculateNewInputs()
            print "[+]=====> Received inputs \n",
            for lit in newIn:
                for a, v in lit.items():
                    print str(format(a,'x')),v
                print "\n"
                if(lit in previousInputs):
                    print "not adding " + str(lit)
                else:
                    nextInputs.append(lit)


            previousInputs.append(inp)
            gc.collect()
    sys.exit(0)

