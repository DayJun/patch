from pwn import *
from capstone import *
from capstone.x86 import X86_INS_PUSH
import lief
import struct
import os
import argparse
from shellcode import myShellCraft

class ELFPatchUtils():
    def __init__(self, binary):
        self.e = lief.parse(binary)
        self.elf = ELF(binary, checksec=False)
        self.originEntryPoint = self.e.entrypoint
        self.modifiedPtr = 0

    def addDataSegment(self, size):
        segment_add = lief.ELF.Segment()
        segment_add.type = lief.ELF.SEGMENT_TYPES.LOAD
        segment_add.alignment = 8
        segment_add.add(lief.ELF.SEGMENT_FLAGS.W)
        segment_add.add(lief.ELF.SEGMENT_FLAGS.R)
        segment_add.content = [0 for _ in range(size)]
        segment = self.e.add(segment_add, base=0x20000)
        log.success("add data segment succeed!")
        return segment

    def addHookSegment(self):
        segment_add = lief.ELF.Segment()
        segment_add.type = lief.ELF.SEGMENT_TYPES.LOAD
        segment_add.alignment = 8
        segment_add.add(lief.ELF.SEGMENT_FLAGS.X)
        segment_add.add(lief.ELF.SEGMENT_FLAGS.R)
        segment_add.content = [0 for _ in range(0x1000)]
        segment = self.e.add(segment_add, base=0x10000)
        log.success("add hook segment succeed!")
        return segment

    def getLOADSegment(self):
        for segment in self.e.segments:
            if segment.type == lief.ELF.SEGMENT_TYPES.LOAD and segment.flags & lief.ELF.SEGMENT_FLAGS.X != 0:
                return segment

    def getSectionByName(self, name):
        for section in self.e.sections:
            if section.name == name:
                return section

    def getPltAddress(self, name, static=False, pltAddress=None):
        if name == 'nop':
            return 0
        if not static:
            try:
                return self.elf.plt[name]
            except:
                log.warn("No %s function" %(name))
                return 0
        else:
            return pltAddress[name]

    def genShellcode(self, shellcodeName, args=None):
        if self.e.header.identity_class == lief.ELF.ELF_CLASS.CLASS64:
            context.arch = 'amd64'
            init_asm = ''
            if shellcodeName == 'initLog':
                init_asm = asm(myShellCraft.init_shellcode64[shellcodeName].format(hex(args[0]), hex(args[1])))
                shellcode = init_asm
            elif shellcodeName == 'readLog':
                shellcode = asm(myShellCraft.shellcode64[shellcodeName].format(hex(args[0]), hex(args[1]+0x8)))
            elif shellcodeName == '__isoc99_scanfLog':
                shellcode = asm(myShellCraft.shellcode64[shellcodeName].format(hex(args[0]), hex(args[1]+8)))
                

        elif self.e.header.identity_class == lief.ELF.ELF_CLASS.CLASS32:
            context.arch='i386'
            init_asm = ''
            if shellcodeName == 'initLog':
                init_asm = asm(myShellCraft.init_shellcode32[shellcodeName].format(hex(args[0]), hex(args[1])))
                shellcode = init_asm
            elif shellcodeName == 'readLog':
                shellcode = asm(myShellCraft.shellcode32[shellcodeName].format(hex(args[0]), hex(args[1]+0x8)))
            elif shellcodeName == '__isoc99_scanfLog':
                shellcode = asm(myShellCraft.shellcode32[shellcodeName].format(hex(args[0]), hex(args[1]+8)))
        code = []
        try:
            for i in shellcode:
                code.append(ord(i))
        except:
            raise Exception("No such shellcode")
        return code, len(init_asm)
    def getFunctionAddress(self, func_name, static):
        if static is False or func_name == 'nop':
            if not self.e.is_pie:
                func_plt_address = self.getPltAddress(func_name)
            else:
                func_plt_address = self.getPltAddress(func_name) - self.originEntryPoint + self.e.entrypoint
            return func_plt_address
        else:
            try:
                return func_name
            except:
                raise Exception("With --static please enter address@shellcode")

    def hookCallPlt(self, funcShellcodeName, isStatic, args):
        data_segment_added = self.addDataSegment(0x100)
        oldEntrypoint = self.e.entrypoint
        segment_add = self.addHookSegment()
        for funcShellcode in funcShellcodeName:
            func_name, shellcodeName = funcShellcode.split('@')
            if isStatic and func_name != 'nop':
                func_name = eval(func_name)
            shellcode, init_length = self.genShellcode(shellcodeName, [segment_add.virtual_address, data_segment_added.virtual_address])
            prevShellcode = segment_add.content[:self.modifiedPtr]
            prevShellcode += shellcode
            shellcodeLength = len(shellcode)
            segment_add.content = prevShellcode
            if init_length != 0:
                patch_address = segment_add.virtual_address+init_length-5
                init_offset = self.e.entrypoint - patch_address - 5
                patched_code = [ord(i) for i in (myShellCraft.opcode['jmp_offset']+struct.pack('i', init_offset))]
                self.e.patch_address(patch_address, patched_code)
            if func_name == '__isoc99_scanf':
                patch_address = segment_add.virtual_address+self.modifiedPtr+shellcodeLength-5
                if isStatic:
                    patch_offset = self.getPltAddress(func_name, isStatic, args) - patch_address - 5    
                else:
                    patch_offset = self.getPltAddress(func_name) - patch_address - 5
                patched_code = [ord(i) for i in (myShellCraft.opcode['jmp_offset']+struct.pack('i', patch_offset))]
                self.e.patch_address(patch_address, patched_code)
            LOADSegment = self.getLOADSegment()
            textSection = self.getSectionByName('.text')
            code_offset = textSection.file_offset
            func_plt_address = self.getFunctionAddress(func_name, isStatic)
            if func_plt_address == 0:
                self.modifiedPtr += shellcodeLength
                continue
            if self.e.header.identity_class == lief.ELF.ELF_CLASS.CLASS64:
                md = Cs(CS_ARCH_X86, CS_MODE_64)
            elif self.e.header.identity_class == lief.ELF.ELF_CLASS.CLASS32:
                md = Cs(CS_ARCH_X86, CS_MODE_32)
            code = bytearray(textSection.content)
            offset_need_to_modified = []
            findFunctionFlag = 0
            if not isStatic:
                for i in md.disasm(code, LOADSegment.virtual_address+code_offset):
                    if i.mnemonic == 'call':
                        if i.op_str.startswith('0x'):
                            call_address = int(i.op_str, 16)
                            if call_address == func_plt_address or call_address == func_plt_address + 4:
                                findFunctionFlag = 1
                                offset_need_to_modified.append(i.address)
                                log.success("patched 0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
            else:
                offset_need_to_modified = [i for i in func_name]
                findFunctionFlag = 1
            if findFunctionFlag == 0:
                raise Exception("[-] can not find target function!")
            for address in offset_need_to_modified:
                if not self.e.is_pie:
                    modified_offset = address - (self.e.entrypoint & ~0xfffff) - code_offset
                else:
                    modified_offset = address
                offset = segment_add.virtual_address + init_length + self.modifiedPtr - address - 5
                patched_code = [ord(i) for i in (myShellCraft.opcode['call_offset'] + struct.pack('i', offset))]
                self.e.patch_address(address, patched_code)
                log.success("patched 0x%x" %(address))
            self.modifiedPtr += len(shellcode)
        self.e.header.entrypoint = segment_add.virtual_address
        log.success("new entrypoint: 0x%x" %(self.e.entrypoint))
        outfile = self.e.name+'_patch'
        self.e.write(outfile)
        st = os.stat(outfile)
        os.chmod(outfile, st.st_mode | 0111)
        log.success("patch succeed!")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="AWD patch tool")
    parser.add_argument("bin", help="/path/to/your/input binary")
    parser.add_argument("-s", "--shellcode", action='append', default=[], help="choose shellcode", required=True)
    parser.add_argument("--static", action='store_true', help="static mode")
    parser.add_argument("-p", "--plt", help="plt address; Need with --static")
    args = parser.parse_args()
    elf = ELFPatchUtils(args.bin)
    #elf.hookPlt(args.functions, args.shellcode)
    if not args.static:
        shellcode = ['nop@initLog']
        for s in args.shellcode:
            shellcode.append(s)
        elf.hookCallPlt(shellcode, False)
    elif args.static:
        shellcode = ['nop@initLog']
        for s in args.shellcode:
            shellcode.append(s)
        try:
            plt = eval(args.plt)
        except:
            raise Exception("args Error")
        elf.hookCallPlt(shellcode, True, plt)
