from collections import deque
from capstone.x86_const import X86_OP_MEM, X86_OP_REG, X86_OP_IMM
import random
from capstone import *
from triton import *
from typing import Mapping
from capstone import Cs
from unicorn.unicorn_const import UC_MEM_READ, UC_MEM_WRITE
from qiling import Qiling
from qiling.const import QL_ARCH
from collections import namedtuple, deque
from capstone import *
from keystone import *

from typing import Mapping, NamedTuple, Union, List
from enum import IntEnum

__all__ = [
    "Sanctum",
    "DebugLevel",
]

SYM_ACC_REG = False

class DebugLevel(IntEnum):
    NONE = 0
    INFO =  1 << 1
    FUNC_INSN = 1 << 2
    FUNC_SYMDATA = 1 << 3
    FUNC_EVAL = 1 << 4
    HARD_DEBUG = 1 << 5 

class SupportedInstructionsList(List):

    def __init__(self):
        super().__init__()
        self.instructions = ['movzx', 'mov', 'xor', 'cmp', 'movsx', "lea", "add", "imul"]

    def __contains__(self, instruction):
        return instruction in self.instructions


class Instruction:

    def __init__(self, cinsn):
        self.op1 = None
        self.op2 = None
        self.op3 = None
        self.cinsn = cinsn
        self.v_op1 = None
        self.v_op2 = None
        self.v_op3 = None


class HookedAddr(NamedTuple):
    value: str
    name: int


gctx = TritonContext(ARCH.X86_64)
g_ast = gctx.getAstContext()
gctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)


class _Color:

    def __init__(self):
        self.color = '\033[38;5;{}m'.format(random.randint(30, 200))

    def __repr__(self):
        return self.color


class _SymValue:

    def __init__(self, value):
        self.ast_value = value

    def __repr__(self):
        return str(self.ast_value)

    def set(self, value):
        self.ast_value = value

    def clone(self):
        return _SymValue(self.ast_value)


class _SymData(object):

    def __init__(self, name, high, low, parent=None, hookname=None):
        self.parent = parent
        self.acc_t = SYM_ACC_REG
        self.hookname = hookname
        if parent:
            low += parent.low
            high += parent.low
            assert high <= parent.high
            self.sym = parent.sym
            self.color = parent.color

        else:
            ast_name = str(name) if hookname is None else hookname
            self.sym = _SymValue(
                g_ast.variable(gctx.newSymbolicVariable(64, ast_name)))
            self.color = _Color()

        assert high >= low
        self.dat = name, high, low

    def instruction(func):

        def _winstr(self, *args, **kw):
            res = func(self, *args, **kw)
            self._update()
            return res

        return _winstr

    @property
    def name(self):
        return self.dat[0]

    @property
    def high(self):
        return self.dat[1]

    @property
    def low(self):
        return self.dat[2]

    @property
    def bits(self):
        return self.high - self.low + 1

    def __getitem__(self, index):
        assert isinstance(index, slice) and index.step is None
        return _SymData(self, index.start, index.stop)

    def new(self):
        self.sym = _SymValue(
            g_ast.variable(gctx.newSymbolicVariable(64, self.name)))
        self.color = _Color()
        return self

    def _set(self, target):
        if isinstance(target, _SymData):
            self.sym = target.sym.clone()
            self.color = target.color

        elif isinstance(target, _SymValue):
            self.sym = target.clone()
            
        else:
            raise Exception("Cannot set a non symbolic value")

        if self.acc_t:
            self.sym.ast_value = self.sym.ast_value & ((1 << self.bits) - 1)
        return self

    def set(self, target):
        if self.name in SymbolicRegistersFactory:
            for reg in SymbolicRegistersFactory[self.name]:
                reg._set(target)
        else:
            self._set(target)

    def _update(self):
        self.set(self)

    @instruction
    def __xor__(self, second_value):
        # apply compute on the current self.sym, but return self
        if isinstance(second_value, _SymData):
            self.sym.ast_value = self.sym.ast_value ^ second_value.sym.ast_value
        else:
            self.sym.ast_value = self.sym.ast_value ^ second_value

        return self
    
    @instruction
    def __add__(self, second_value):
        if isinstance(second_value, _SymData):
            self.sym.ast_value = self.sym.ast_value + second_value.sym.ast_value
        else:
            self.sym.ast_value = self.sym.ast_value + second_value
            
        return self
       
    @instruction     
    def __mul__(self, second_value):
        if isinstance(second_value, _SymData):
            self.sym.ast_value = self.sym.ast_value * second_value.sym.ast_value
        else:
            self.sym.ast_value = self.sym.ast_value * second_value
         
        return self

    def __repr__(self) -> str:
        return self.sym.__repr__()


rax = _SymData('rax', 63, 0)
rcx = _SymData('rcx', 63, 0)
rdx = _SymData('rdx', 63, 0)
rbx = _SymData('rbx', 63, 0)
rbp = _SymData('rbp', 63, 0)
rsi = _SymData('rsi', 63, 0)
rdi = _SymData('rdi', 63, 0)
r8 = _SymData('r8', 63, 0)
r9 = _SymData('r9', 63, 0)
r10 = _SymData('r10', 63, 0)
r11 = _SymData('r11', 63, 0)
r12 = _SymData('r12', 63, 0)
r13 = _SymData('r13', 63, 0)
r14 = _SymData('r14', 63, 0)
r15 = _SymData('r15', 63, 0)

eax = _SymData('eax', 31, 0, rax)
ecx = _SymData('ecx', 31, 0, rcx)
edx = _SymData('edx', 31, 0, rdx)
ebx = _SymData('ebx', 31, 0, rbx)
ebp = _SymData('ebp', 31, 0, rbp)
esi = _SymData('esi', 31, 0, rsi)
edi = _SymData('edi', 31, 0, rdi)
r8d = _SymData('r8d', 31, 0, r8)
r9d = _SymData('r9d', 31, 0, r9)
r10d = _SymData('r10d', 31, 0, r10)
r11d = _SymData('r11d', 31, 0, r11)
r12d = _SymData('r12d', 31, 0, r12)
r13d = _SymData('r13d', 31, 0, r13)
r14d = _SymData('r14d', 31, 0, r14)
r15d = _SymData('r15d', 31, 0, r15)

ax = _SymData('ax', 15, 0, eax)
cx = _SymData('cx', 15, 0, ecx)
dx = _SymData('dx', 15, 0, edx)
bx = _SymData('bx', 15, 0, ebx)
bp = _SymData('bp', 15, 0, ebp)
si = _SymData('si', 15, 0, esi)
di = _SymData('di', 15, 0, edi)
r8w = _SymData('r8w', 15, 0, r8d)
r9w = _SymData('r9w', 15, 0, r9d)
r10w = _SymData('r10w', 15, 0, r10d)
r11w = _SymData('r11w', 15, 0, r11d)
r12w = _SymData('r12w', 15, 0, r12d)
r13w = _SymData('r13w', 15, 0, r13d)
r14w = _SymData('r14w', 15, 0, r14d)
r15w = _SymData('r15w', 15, 0, r15d)

al = _SymData('al', 7, 0, ax)
cl = _SymData('cl', 7, 0, cx)
dl = _SymData('dl', 7, 0, dx)
bl = _SymData('bl', 7, 0, bx)
bpl = _SymData('bpl', 7, 0, bp)
sil = _SymData('sil', 7, 0, si)
dil = _SymData('dil', 7, 0, di)
r8b = _SymData('r8b', 7, 0, r8w)
r9b = _SymData('r9b', 7, 0, r9w)
r10b = _SymData('r10b', 7, 0, r10w)
r11b = _SymData('r11b', 7, 0, r11w)
r12b = _SymData('r12b', 7, 0, r12w)
r13b = _SymData('r13b', 7, 0, r13w)
r14b = _SymData('r14b', 7, 0, r14w)
r15b = _SymData('r15b', 7, 0, r15w)

ah = _SymData('ah', 15, 8, ax)
ch = _SymData('ch', 15, 8, cx)
dh = _SymData('dh', 15, 8, dx)
bh = _SymData('bh', 15, 8, bx)


SymbolicRegistersFactory = {
'ah': [rax, eax, ax, ah, al],
'al': [rax, eax, ax, ah, al],
'ax': [rax, eax, ax, ah, al],
'bh': [rbx, ebx, bx, bh, bl],
'bl': [rbx, ebx, bx, bh, bl],
'bp': [rbp, ebp, bp, bpl],
'bpl': [rbp, ebp, bp, bpl],
'bx': [rbx, ebx, bx, bh, bl],
'ch': [rcx, ecx, cx, ch, cl],
'cl': [rcx, ecx, cx, ch, cl],
'cx': [rcx, ecx, cx, ch, cl],
'dh': [rdx, edx, dx, dh, dl],
'di': [rdi, edi, di, dil],
'dil': [rdi, edi, di, dil],
'dl': [rdx, edx, dx, dh, dl],
'dx': [rdx, edx, dx, dh, dl],
'eax': [rax, eax, ax, ah, al],
'ebp': [rbp, ebp, bp, bpl],
'ebx': [rbx, ebx, bx, bh, bl],
'ecx': [rcx, ecx, cx, ch, cl],
'edi': [rdi, edi, di, dil],
'edx': [rdx, edx, dx, dh, dl],
'esi': [rsi, esi, si, sil],
'r10': [r10, r10d, r10w, r10b],
'r10b': [r10, r10d, r10w, r10b],
'r10d': [r10, r10d, r10w, r10b],
'r10w': [r10, r10d, r10w, r10b],
'r11': [r11, r11d, r11w, r11b],
'r11b': [r11, r11d, r11w, r11b],
'r11d': [r11, r11d, r11w, r11b],
'r11w': [r11, r11d, r11w, r11b],
'r12': [r12, r12d, r12w, r12b],
'r12b': [r12, r12d, r12w, r12b],
'r12d': [r12, r12d, r12w, r12b],
'r12w': [r12, r12d, r12w, r12b],
'r13': [r13, r13d, r13w, r13b],
'r13b': [r13, r13d, r13w, r13b],
'r13d': [r13, r13d, r13w, r13b],
'r13w': [r13, r13d, r13w, r13b],
'r14': [r14, r14d, r14w, r14b],
'r14b': [r14, r14d, r14w, r14b],
'r14d': [r14, r14d, r14w, r14b],
'r14w': [r14, r14d, r14w, r14b],
'r15': [r15, r15d, r15w, r15b],
'r15b': [r15, r15d, r15w, r15b],
'r15d': [r15, r15d, r15w, r15b],
'r15w': [r15, r15d, r15w, r15b],
'r8': [r8, r8d, r8w, r8b],
'r8b': [r8, r8d, r8w, r8b],
'r8d': [r8, r8d, r8w, r8b],
'r8w': [r8, r8d, r8w, r8b],
'r9': [r9, r9d, r9w, r9b],
'r9b': [r9, r9d, r9w, r9b],
'r9d': [r9, r9d, r9w, r9b],
'r9w': [r9, r9d, r9w, r9b],
'rax': [rax, eax, ax, ah, al],
'rbp': [rbp, ebp, bp, bpl],
'rbx': [rbx, ebx, bx, bh, bl],
'rcx': [rcx, ecx, cx, ch, cl],
'rdi': [rdi, edi, di, dil],
'rdx': [rdx, edx, dx, dh, dl],
'rsi': [rsi, esi, si, sil],
'si': [rsi, esi, si, sil],
'sil': [rsi, esi, si, sil]
}


def get_insn(ql):
    
    if ql.arch.type == QL_ARCH.X8664:
        pc = ql.arch.regs.eip
    else:
        pc = ql.arch.regs.rip
    
    md = ql.arch.disassembler
    buf = ql.mem.read(pc, 0x10)
    return next(md.disasm(buf, pc))


def get_pc(ql):
    if ql.arch.type == QL_ARCH.X8664:
        return ql.arch.regs.eip
    else:
        return ql.arch.regs.rip

def log(conf_debug, info, ldebug):

    
    if ldebug & conf_debug:
        print("\033[95m" + "[+]" + "\033[0m"  + "\033[2m", info, "\033[0m")
        
def op_xor(v1, v2):
    return v1 ^ v2

def op_add(v1, v2):
    return v1 + v2

def op_imul(v1, v2):
    return v1 * v2

class _State:

    def __init__(self, ql, accurate_tracing=False, debug_level=DebugLevel.NONE) -> None:
        self.dict = {}
        self.stack = deque()
        self.ql = ql
        self.acc_t = accurate_tracing
        self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
        self.ldebug = debug_level

    def __getitem__(self, key):
        return self.dict[key]

    def __setitem__(self, key, value):
        self.dict[key] = value

    def __contains__(self, key):
        return key in self.dict
    
    def _compute(self, regname, operation, *args):
        if len(args) == 2:
            symdata1, symdata2 = args
        else:
            raise Exception("Not implemented")
        
        if isinstance(symdata1, _SymData):
            result = operation(symdata1, symdata2)
        else:
            symvalue = symdata2.sym.clone()
            result = operation(symvalue.ast_value, symdata1)
            symdata1 = self.new_symdata(regname)
    
        return result if isinstance(result, _SymData) else self.new_symdata(regname, result)

    def _mov(self, symdata1, symdata2, regname):

        # remove SymbolicRegister from dict if it is overwritten
        if not isinstance(symdata2, _SymData):
            self.delete_symbolic_var(symdata1.name)
            return None

        elif not isinstance(symdata1, _SymData) and isinstance(
                symdata2, _SymData):
            symdata1 = self.new_symdata(regname)
            symdata1.set(symdata2)
            return symdata1

        elif isinstance(symdata1, _SymData) and isinstance(symdata2, _SymData):
            symdata1.set(symdata2)
            return symdata1

        else:
            raise Exception("Not implemented")
        

    def _xor(self, regname, *args):
        return self._compute(regname, op_xor, *args)
    
    def _add(self, regname, *args):
        return self._compute(regname, op_add, *args)
    
    def _imul(self, regname, *args):
        return self._compute(regname, op_imul, *args)



    def process_insn(self, ql, Insn, mem_access, haddr=False, hname=None):


        sym_access = haddr or hex(mem_access) in self.dict

        if len(Insn.cinsn.operands) > 0:
            
            Insn.op1 = Insn.cinsn.operands[0]
            if Insn.op1.type == X86_OP_REG:
                regname = self.cs.reg_name(Insn.op1.reg)
                if regname in self.dict:
                    Insn.v_op1 = self.dict[regname]
                else:
                    Insn.v_op1 = ql.arch.regs.read(regname.upper())
                    
               # mem write
            if Insn.op1.type == X86_OP_MEM and (Insn.cinsn.mnemonic != "cmp" or sym_access):
                if hex(mem_access) in self.dict:
                    log(self.ldebug, f"Loading a value from a previous symbolic memory write {self.dict[hex(mem_access)]}", DebugLevel.FUNC_INSN)
                    Insn.v_op1 = self.dict[hex(mem_access)]
                else:
                    log(self.ldebug, f"Instanciate a sym memory write {self.dict[hex(mem_access)]} {hname}", DebugLevel.FUNC_INSN)
                    Insn.v_op1 = self.new_symdata(hex(mem_access), hname=hname)
                    # value_op2 is a register
            elif Insn.op1.type == X86_OP_MEM:
                Insn.v_op1 = ql.mem.read(mem_access, 1)[0]
                
            assert Insn.v_op1 is not None
                
        if len(Insn.cinsn.operands) > 1:
            
            Insn.op2 = Insn.cinsn.operands[1]

            if Insn.op2.type == X86_OP_REG:
                regname = self.cs.reg_name(Insn.op2.reg)
                # if is a symbolic register
                if regname in self.dict:
                    Insn.v_op2 = self.dict[regname]
                # else get concrete value
                else:
                    Insn.v_op2 = ql.arch.regs.read(regname.upper())
                    
            if Insn.op2.type == X86_OP_IMM:
                Insn.v_op2 = Insn.op2.imm

            # we read a value from memory, and the address is hooked/symbolic
            if Insn.op2.type == X86_OP_MEM and haddr:
                # instanciate a symbolic memory inside the destination register
                if hex(mem_access) in self.dict:
                    log(self.ldebug, f"Loading a value from a previous symbolic memory write {self.dict[hex(mem_access)]}", DebugLevel.FUNC_INSN)
                    Insn.v_op2 = self.dict[hex(mem_access)]
                else:
                    regname = self.cs.reg_name(Insn.op1.reg)
                    Insn.v_op2 = self.new_symdata(hex(mem_access), hname=hname)

            elif Insn.op2.type == X86_OP_MEM:
                if hex(mem_access) in self.dict:
                    Insn.v_op2 = self.dict[hex(mem_access)]
                else:
                    Insn.v_op2 = ql.mem.read(mem_access, 1)[0]
                    

            assert Insn.v_op1 is not None
            assert Insn.v_op2 is not None

        return Insn

    def new_symdata(self, var_name, hname=None):
        log(self.ldebug, f"Instanciate symbolic var {var_name} {hname}", DebugLevel.FUNC_SYMDATA)
        if var_name in SymbolicRegistersFactory:
            for reg in SymbolicRegistersFactory[var_name]:
                reg.new()
                self.dict[reg.name] = reg
                
        else:
            self.dict[var_name] = _SymData(var_name, 63, 0, hookname=hname)

        return self.dict[var_name]

    def delete_symbolic_var(self, var_name):

        log(self.ldebug, f"Deleting symbolic var {var_name}", DebugLevel.FUNC_SYMDATA)
        if var_name in SymbolicRegistersFactory:
            for reg in SymbolicRegistersFactory[var_name]:
                self.dict[reg.name].new()
                del self.dict[reg.name]   
        else: 
            self.dict[reg.name].new()
            del self.dict[var_name]

    def chk_sym_op(self, mem_access, insn):

        for op in insn.operands:
            # Check if the operand is a register
            if op.type == X86_OP_REG:
                regname = self.cs.reg_name(op.reg)
                # If the register is in the dictionary, set the flag
                if regname in self.dict:
                    log(self.ldebug, f"Symbolic register found in {regname} => {self.dict[regname]}", DebugLevel.FUNC_SYMDATA)
                    return True

            # Check if the operand is a memory access
            if op.type == X86_OP_MEM:
                if hex(mem_access) in self.dict:
                    log(self.ldebug, f"Symbolic memory found in {hex(mem_access)} => {self.dict[hex(mem_access)]}", DebugLevel.FUNC_SYMDATA)
                    return True
        return False

    def eval(self, mem_access, haddr=False, hname=None):

        # hooked addresses are also one whitch have been written in
        # memory by a previous symbolic write
        if not haddr:
            haddr = hex(mem_access) in self.dict

        if len(self.dict) == 0 and not haddr:
            return False

        insn = get_insn(self.ql)

        log(self.ldebug, f"Instruction {insn} {haddr} {hname}", DebugLevel.FUNC_EVAL)

        if not self.chk_sym_op(mem_access, insn) and not haddr:
            return

        if insn.mnemonic in SupportedInstructionsList():

            Insn = self.process_insn(self.ql, Instruction(insn), mem_access, haddr=haddr, hname=hname)
            res_operation = None

            if insn.mnemonic.startswith('mov'):
                regname = self.cs.reg_name(Insn.op1.reg)
                if Insn.op1.type == X86_OP_REG and Insn.op2.type != X86_OP_REG and not haddr:
                    self.delete_symbolic_var(regname)
                    return
                res_operation = self._mov(Insn.v_op1, Insn.v_op2, regname)

            elif insn.mnemonic.startswith('xor'):
    
                res_operation = self._xor(self.cs.reg_name(Insn.op1.reg), Insn.v_op1,
                                    Insn.v_op2)
                
            elif insn.mnemonic.startswith('add'):
                res_operation = self._add(self.cs.reg_name(Insn.op1.reg), Insn.v_op1,
                                    Insn.v_op2)
                
            elif insn.mnemonic.startswith('imul'):
                res_operation = self._imul(self.cs.reg_name(Insn.op1.reg), Insn.v_op1,
                                    Insn.v_op2)
                
            elif insn.mnemonic.startswith('lea'):
                regname = self.cs.reg_name(Insn.op1.reg)
                self.delete_symbolic_var(regname)
                print("\033[95m", hex(get_pc(self.ql)), insn.mnemonic, insn.op_str, "\033[0m", end=" ")
                print("\033[95m===> Please ensure that the load is static and does not depend on symbolic value\033[0m")
                return

            elif insn.mnemonic.startswith('cmp'):
                symdata = None  
                if isinstance(Insn.v_op1,_SymData):
                    symdata = Insn.v_op1
   
                elif isinstance(Insn.v_op2,_SymData):
                    symdata = Insn.v_op2
                    
                if isinstance(Insn.v_op1, int):
                    Insn.v_op1 = hex(Insn.v_op1)
                    
                if isinstance(Insn.v_op2, int):
                    Insn.v_op2 = hex(Insn.v_op2)
             
                print("\033[100m===> cmp", str(Insn.v_op1) + "==" + str(Insn.v_op2),"\033[0m")

                print("==> Synthesize version: ",
                      gctx.synthesize(symdata.sym.ast_value))
                

            if not isinstance(res_operation, _SymData):
                log(self.ldebug, f"Result of the operation no an instance of symdata {res_operation}", DebugLevel.FUNC_EVAL)
                return

            print(res_operation.color, hex(get_pc(self.ql)), insn.mnemonic,
                  insn.op_str, "\033[0m\033[2m==>", res_operation, '\033[0m')

        else:
            print('\033[93m', "Instruction currently not supported ---> ",
                  insn.mnemonic, insn.op_str, '\033[0m')
            
        if self.ldebug & DebugLevel.HARD_DEBUG:
            for regname in self.dict.keys():
                print("===>", regname, self.dict[regname])
                


    def __repr__(self) -> str:
        rep = [f'{key} = {value}' for key, value in self.dict.items()]
        return ''.join(rep)



def __map_regs() -> Mapping[int, int]:
    """Map Capstone x86 regs definitions to Unicorn's.
    """

    from capstone import x86_const as cs_x86_const
    from unicorn import x86_const as uc_x86_const

    def __canonicalized_mapping(module, prefix: str) -> Mapping[str, int]:
        return dict((k[len(prefix):], getattr(module, k)) for k in dir(module)
                    if k.startswith(prefix))

    cs_x86_regs = __canonicalized_mapping(cs_x86_const, 'X86_REG')
    uc_x86_regs = __canonicalized_mapping(uc_x86_const, 'UC_X86_REG')

    return dict((cs_x86_regs[k], uc_x86_regs[k]) for k in cs_x86_regs
                if k in uc_x86_regs)


# capstone to unicorn regs mapping
CS_UC_REGS = __map_regs()


class Sanctum():

    def __init__(self, ql, accurate_tracing=False, debug_level=DebugLevel.NONE) -> None:
        self.tainted_mem_addr = {}
        self.ql = ql
        self.state = _State(ql, accurate_tracing, debug_level)
            # check 32 or 64 bit
        if ql.arch.type == QL_ARCH.X8664:
            self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
            self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
        else: 
            self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
            self.ks = Ks(KS_ARCH_X86, KS_MODE_32)
            
        self.text_base = ql.loader.images[0].base
        self.text_end = ql.loader.images[0].end

    def check_scope(self, ql):
        
        if ql.arch.type == QL_ARCH.X8664:
            pc = ql.arch.regs.rip
        else:
            pc = ql.arch.regs.eip

        if pc < self.text_base or pc >= self.text_end:
            return False
        return True

    def get_hname(self, addr):
        if addr in self.tainted_mem_addr:
            return self.tainted_mem_addr[addr].name
        return hex(addr)

    def hook_address(self, addr: int, expected_value: bytearray,
                     var_name: str):

        if '%d' not in var_name:
            raise ValueError("var_name must contain a %d")

        if not isinstance(expected_value, bytearray):
            raise ValueError("expected_value must be a bytearray")

        if len(expected_value) == 0:
            raise ValueError("expected_value must have at least 1 byte")

        for i in range(len(expected_value)):
            self.tainted_mem_addr[addr + i] = HookedAddr(
                expected_value[i], var_name % i)

    def mem_read(self, ql: Qiling, access: int, address: int, size: int,
                 value: int):
        # only read accesses are expected here
        assert access == UC_MEM_READ
        if not self.check_scope(ql):
            return

        # read value from address
        value = ql.mem.read(address, 1)[0]

        # check if the address is tainted
        symaddr = address in self.tainted_mem_addr and self.tainted_mem_addr[
            address].value == value

        han = self.get_hname(address)

        self.state.eval(address, symaddr, hname=han)

    # This code checks if the hook is in scope. If it is, it evaluates the expression.

    def mem_write(self, ql: Qiling, access: int, address: int, size: int,
                  value: int):
        assert access == UC_MEM_WRITE
        if not self.check_scope(ql):
            return

        han = self.get_hname(address)

        self.state.eval(address, hname=han)

    def hook_code(self, ql: Qiling, address: int, size):
        # log only instructions located in the .text section
        if not self.check_scope(ql):
            return
        
        # if there is a mem_read or mem_write , we do not continue
        if self.check_mem_access(get_insn(ql)):
            return
        
        self.state.eval(address)

    def check_mem_access(self, insn):
        for op in insn.operands:
            if op.type == X86_OP_MEM:
                return

    def run(self):
        md = self.ql.arch.disassembler
        md.detail = True
        self.ql.hook_mem_read(self.mem_read)
        self.ql.hook_mem_write(self.mem_write)
        self.ql.hook_code(self.hook_code)
        self.ql.run()
