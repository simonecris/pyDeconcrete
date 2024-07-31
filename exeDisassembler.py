import os.path
import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs, CS_MODE_64
from abc import ABC, abstractmethod

SECRET_KEY_LEN = 16


class BinaryDisassembler(ABC):
    def __init__(self, filepath, mode):
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f'Cannot find {filepath}')

        self.ARCH = CS_ARCH_X86
        if mode == 'x64':
            self.MODE = CS_MODE_64
        else:
            self.MODE = CS_MODE_32

        self.SECRET_KEY = ''
        self.SECRET_NUM = ''
        try:
            self._load_binary(filepath)
        except:
            raise Exception('Cannot parse provided file!')

    @abstractmethod
    def _load_binary(self, filepath):
        pass

    @abstractmethod
    def get_secrets(self):
        pass


class WindowsDisassembler(BinaryDisassembler):

    def __init__(self, filepath, mode, secret_key_len):
        super().__init__(filepath, mode)
        self.SECRET_KEY_LEN = secret_key_len

    def _load_binary(self, filepath):
        self.pe = pefile.PE(filepath)
        self.ImageBase = self.pe.OPTIONAL_HEADER.ImageBase

    def _find_section(self, offset) -> tuple[pefile.SectionStructure, int] | None:
        if self.ImageBase:
            offset -= self.ImageBase

        for section in self.pe.sections:
            section_offset = section.VirtualAddress
            section_size = section.SizeOfRawData
            if section_offset <= offset < section_offset + section_size:
                if self.ImageBase:
                    section_offset += self.ImageBase
                return section, section_offset
        raise Exception(f'Cannot find section that contains {hex(offset)}')

    def _get_text_section_headers(self) -> pefile.SectionStructure:

        virtual_addresses = []
        for section in self.pe.sections:
            virtual_addresses.append(section.VirtualAddress)
            if b'.text' in section.Name:
                print(f'[-] Found [.text] section using section name starting at [{hex(section.PointerToRawData)}h]')
                return section

        # if not found in section name, search using BaseOfCode address
        base_of_code = self.pe.OPTIONAL_HEADER.BaseOfCode
        if base_of_code:
            # Search using virtual addresses
            if base_of_code in virtual_addresses:
                print(f'[-] Found .text section using virtual addresses match with BaseOfCode Header.')
                return self.pe.sections[virtual_addresses.index(base_of_code)]

            # Search for BaseOfCode inside a section
            virtual_addresses.append(base_of_code)
            virtual_addresses.sort()
            if virtual_addresses.index(base_of_code) != 0:
                print(f'[-] Found .text section using virtual addresses match with BaseOfCode Header.')
                return self.pe.sections[virtual_addresses.index(base_of_code) - 1]
            else:
                # this means we failed to locate it
                raise Exception('Cannot find .text section!')

    def _get_text_section(self):
        text_section_headers = self._get_text_section_headers()

        code = text_section_headers.get_data()
        va = text_section_headers.VirtualAddress
        if self.ImageBase:
            va += self.ImageBase

        return code, va

    def get_secrets(self):

        text_section, text_section_VA = self._get_text_section()
        md = Cs(self.ARCH, self.MODE)

        if self.ARCH == CS_ARCH_X86 and self.MODE == CS_MODE_64:
            pass

        cmp_address: int = 0
        jump_to_address: int = 0

        # The GetSecretKey() method performs a
        # for(i = 0 ; i < SECRET_KEY_LEN ; ++i)
        # {...}
        # We'll search for that OPCODE:
        # CMP Register, SECRET_KEY_LEN
        # JB ADDRESS

        # Search for "CMP ECX, 0x10; JB ADDR"
        for instr_cmp in md.disasm(text_section, text_section_VA):
            if instr_cmp.mnemonic == 'cmp' and instr_cmp.op_str == f'ecx, {hex(SECRET_KEY_LEN)}':
                next_instr_RVA = instr_cmp.address - text_section_VA
                next_insn = next(
                    md.disasm(text_section[next_instr_RVA + instr_cmp.size:], instr_cmp.address + instr_cmp.size))
                if next_insn.mnemonic == 'jb':
                    cmp_address = instr_cmp.address
                    print(
                        f'[-] Found \'CMP ECX, {hex(SECRET_KEY_LEN)}\' instruction at [.text][{cmp_address:x}h]')
                    jump_to_address = int(next_insn.op_str, 16)
                    break
        if not cmp_address or not jump_to_address:
            raise Exception(f"Cannot find opcode for 'CMP ECX, {hex(SECRET_KEY_LEN)}; JB'.")

        # Segui il salto e trova "MOV EAX, VALUE"
        print(f'[-] Following JUMP at [.text][{jump_to_address:x}h]')

        secret_num_address: int = 0
        jump_to_address_RVA = jump_to_address - text_section_VA
        for instr_mov in md.disasm(text_section[jump_to_address_RVA:], jump_to_address):
            if instr_mov.mnemonic == 'mov' and instr_mov.op_str.startswith('eax, '):
                secret_num_address = instr_mov.address
                self.SECRET_NUM = int(instr_mov.op_str.split(', ')[1], 16)
                print(f'[+] Found SECRET_NUM at [.text][{instr_mov.address:x}h] : {hex(self.SECRET_NUM)}')
                break
        if not secret_num_address:
            raise Exception("Cannot find opcode for 'MOV EAX, SECRET_NUM' after the JB.")

        print(f'[-] Searching for SECRET_KEY address...')

        instructions_stack = []
        secret_num_address_RVA = secret_num_address - text_section_VA

        # Should find it within 50 bytes, explore instructions backwards
        backwards_bytes = 50
        for insn in md.disasm(text_section[secret_num_address_RVA - backwards_bytes:],
                              secret_num_address - backwards_bytes):
            if insn.address < secret_num_address:
                instructions_stack.append(insn)
                backwards_bytes -= insn.size
            else:
                break

        secret_key_address: int = 0

        for _ in range(len(instructions_stack)):
            instr = instructions_stack.pop()

            if instr.mnemonic == 'lea' and '[' in instr.op_str:
                # Should be something like LEA RDX, [RIP + OFFSET]
                secret_key_address_str = instr.op_str.split('[')[1][:-1]
                if 'rip' in secret_key_address_str:
                    secret_key_address_str = secret_key_address_str.split(' + ')[1]
                secret_key_address = int(secret_key_address_str, 16) + instr.address + instr.size
                print(f'[+] Found SECRET_KEY address offset at [.text][{instr.address:x}h] : {secret_key_address:x}h')
                break

        if not secret_key_address:
            raise Exception("Cannot find secret key LEA instruction.")

        data_section, data_section_VA = self._find_section(secret_key_address)
        if '.data' not in str(data_section.Name):
            raise Exception(f"SECRET_KEY address offset pointing to {str(data_section.Name)} section, must be data....")

        data_section = data_section.get_data()
        secret_key_address_RVA = secret_key_address - data_section_VA
        self.SECRET_KEY = data_section[secret_key_address_RVA:secret_key_address_RVA + 16]

        return self.SECRET_KEY, self.SECRET_NUM
