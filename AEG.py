from triton import TritonContext, ARCH, Instruction, MemoryAccess, CPUSIZE, MODE, OPCODE
from triton import TritonContext as T
import lief
import gc

import sys

debug = 'detailed'
pcsymvar =None
Triton = TritonContext()
astc=Triton.getAstContext()
MAX_ARGC = 3
MAX_ARG_SIZE = 64
input ={}
frameDepth = 0;
returnStack = []

def initilizeInput():
    global input
    for i in range(MAX_ARG_SIZE * MAX_ARGC):
        input[0x90000000+i] = 0

def printStack():
    print "EBP = " + str(format(Triton.getConcreteRegisterValue(Triton.registers.ebp),'x'))
    print "EBP = " + str(format(Triton.getConcreteRegisterValue(Triton.registers.esp), 'x'))
    ebp = Triton.getConcreteRegisterValue(Triton.registers.ebp)

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
            esp = Triton.getConcreteRegisterValue(Triton.registers.esp)
            retAddr = Triton.getConcreteMemoryValue(MemoryAccess(esp,4))
            returnStack.append(retAddr)
            for ret in returnStack:
                print format(ret, 'x')

        # printStack()
        if inst.getAddress() == 0x804849b or inst.getAddress() == 0x804847a or inst.getAddress() == 0x804844c:
            print "EAX:"+str(format(Triton.getConcreteRegisterValue(Triton.registers.eax),'x')) + \
                  "    EDX:"+str(format(Triton.getConcreteRegisterValue(Triton.registers.edx),'x')) + \
                  "    EBP : "+ str(format(Triton.getConcreteRegisterValue(Triton.registers.ebp),'x')) + \
                  "    EIP : "+ str(format(Triton.getConcreteRegisterValue(Triton.registers.eip),'x'))

        id = Triton.getSymbolicRegisterId(Triton.registers.eax)
        currentEBP = Triton.getConcreteRegisterValue(Triton.registers.ebp)


        if(frameDepth == 0 and inst.getType() == OPCODE.RET):
            break

        if inst.getType() == OPCODE.RET:
            frameDepth-=1;
            evaluatepc()
        if (inst.getAddress() == 0):
            exit(0)
        pc = Triton.getConcreteRegisterValue(Triton.registers.eip)



def evaluatepc():
    print
    print

    if debug=='detailed' :
        print Triton.getSymbolicVariables()
        print "In EvaluatePc--EIP =  " + str(format(Triton.getConcreteRegisterValue(Triton.registers.eip),'x'))

    ipid = Triton.getSymbolicRegisterId(Triton.registers.eip)
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
    currPc = Triton.getConcreteRegisterValue(Triton.registers.eip);
    if (currPc == correctReturnAddr or currPc == int(sys.argv[3], 16)):
        pass
    else:
        Triton.setConcreteRegisterValue(Triton.registers.eip, returnStack.pop())
    currPc = Triton.getConcreteRegisterValue(Triton.registers.eip);

    if(len(model) >=4):
        print "+++++++++++++done+++++++++++++"
        exit(0)



        # exit(0)
    # a=raw_input()
    print
    print


def loadBinary(path):
    binary  = lief.parse(path)
    phdrs  = binary.segments
    for phdr in phdrs:
        size = phdr.physical_size
        vaddr  = phdr.virtual_address
        print '[+] Loading 0x%06x - 0x%06x' %(vaddr, vaddr+size)
        Triton.setConcreteMemoryAreaValue(vaddr, phdr.content)
    return


def setEnvironment():

    #set argv pointers
    for i in range(MAX_ARGC):
        Triton.setConcreteMemoryValue(MemoryAccess(0x80000000+i*4,4),0x090000000+i*MAX_ARG_SIZE)
    #convert argv to symbolic arguments
    Triton.setConcreteRegisterValue(Triton.registers.ebp, 0x7fffffff)
    Triton.setConcreteRegisterValue(Triton.registers.esp, 0x6fffffff)
    Triton.setConcreteMemoryValue(MemoryAccess(0x06ffffffb + 0x0C, 4), 0x80000000)
    Triton.clearPathConstraints()

def setInput(inp):
    global frameDepth
    frameDepth = 0
    global returnStack
    returnStack = []
    Triton.concretizeAllRegister()
    Triton.concretizeAllMemory()
    Triton.convertRegisterToSymbolicVariable(Triton.registers.eip)
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
    Triton.setArchitecture(ARCH.X86)
    # Load the binary


    loadBinary(sys.argv[1])


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
            emulate(int(sys.argv[2],16))
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

