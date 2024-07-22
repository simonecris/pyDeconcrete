import argparse
import pathlib
import sys

import pefile
from os.path import isfile

from exeDisassembler import exe_disassembler

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import struct

SECRET_KEY_LEN = 16  # The key is a md5 digest, so length is fixed at 16.


# https://github.com/Falldog/pyconcrete/blob/master/setup.py#L86


class CompilerEnum:

    def __init__(self, pe):
        self.pe = pe
        self.br = self.BinaryReader(pe)

    def get_opinion(self):
        offset_choice = "Unknown"

        dos_header = self.pe.DOS_HEADER
        nt_header = self.pe.NT_HEADERS

        # Check for Rust
        if self.is_rust():
            return "Rustc"

        # Check for Swift
        section_names = [section.Name.decode().strip('\x00') for section in self.pe.sections]
        if self.is_swift(section_names):
            return "Swift"

        # Check for managed code (.NET)
        if nt_header.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress != 0:
            return "CLI"

        # Determine based on PE Header offset
        if dos_header.e_lfanew == 0x80:
            offset_choice = "GCC_VS"
        elif dos_header.e_lfanew == 0x78:
            offset_choice = "Clang"
        elif dos_header.e_lfanew >= 0x80:
            try:
                val1 = self.br.read_int(0x80)
                val2 = self.br.read_int(0x84)
                if val1 != 0 and val2 != 0 and (val1 ^ val2) == 0x536e6144:  # "DanS"
                    return "VisualStudio"
                if dos_header.e_lfanew == 0x100:
                    offset_choice = "BorlandPascal"
                elif dos_header.e_lfanew == 0x200:
                    offset_choice = "BorlandCpp"
                elif dos_header.e_lfanew > 0x300:
                    return "Unknown"
            except Exception as e:
                pass

        return offset_choice

    def is_rust(self):
        # Check for Rust specific indicators in the PE file
        # This function needs to be implemented based on Rust-specific details
        return False

    def is_swift(self, section_names):
        # Check for Swift specific sections
        swift_sections = [".swift1", ".swift2", ".swift3"]
        return any(section in section_names for section in swift_sections)

    class BinaryReader:
        def __init__(self, pe):
            self.data = pe.__data__

        def read_int(self, offset):
            return int.from_bytes(self.data[offset:offset + 4], byteorder='little')


class ExecutableAnalyzer:
    def __init__(self, file_path):
        if not isfile(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        self.file_path = file_path

    def analyze_file(self):

        with open(self.file_path, 'rb') as f:
            magic = f.read(4)

        os = 'Unknown'
        endian = 'Unknown'
        arch = 'Unknown'
        compiler = 'Unknown'

        if magic.startswith(b'MZ'):
            pe = pefile.PE(self.file_path)
            os = 'Windows'
            endian = 'little'  # PE files are always little-endian
            is_64bit = pe.FILE_HEADER.Machine in [pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64'],
                                                  pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_IA64']]
            arch = 'x64' if is_64bit else 'x32'
            compiler = CompilerEnum(pe).get_opinion()

        elif magic.startswith(b'\x7fELF'):
            raise Exception('Linux ELF files are not supported yet!')
        else:
            raise ValueError("Unsupported file format")

        return os, endian, arch, compiler


class PyDeconcrete:
    def __init__(self, secret_key, secret_num):
        self.AES_BLOCK_SIZE = 16  # AES default block size
        # https://github.com/Falldog/pyconcrete/blob/master/src/pyconcrete_ext/pyconcrete.c#L25

        key = []
        for i in range(SECRET_KEY_LEN):
            key.append(secret_key[i] ^ (secret_num - i))
        # https://github.com/Falldog/pyconcrete/blob/master/setup.py#L107
        self.key = key

    def decrypt_file(self, pye_path):
        pye_path = pathlib.Path(pye_path)
        if not pye_path.exists():
            raise FileNotFoundError(f"File not found: {pye_path}")
        elif pye_path.suffix != '.pye':
            raise Exception(f'The provided file is not a .pye file!')

        pyc_path = pye_path.with_suffix('.pyc')
        if pyc_path.exists():
            raise Exception(f'Can\'t ovveride existing file {pyc_path}')

        with open(pye_path, 'rb') as pye:
            decrypted_pye = self.decrypt_buffer(pye.read())
        with open(pyc_path, 'rb') as pyc:
            pyc.write(decrypted_pye)

        return pyc_path

    def decrypt_buffer(self, cipher_buf):
        # https://github.com/Falldog/pyconcrete/blob/master/src/pyconcrete_ext/pyconcrete.c#L173
        cipher_buf_size = len(cipher_buf)

        if cipher_buf_size % self.AES_BLOCK_SIZE != 0:
            raise ValueError(f"File content not a multiple of {self.AES_BLOCK_SIZE}.")

        # Decrypt the last block first to get the padding size
        cipher = AES.new(self.key, AES.MODE_ECB)

        last_block = cipher_buf[-self.AES_BLOCK_SIZE:]
        decrypted_last_block = cipher.decrypt(last_block)
        padding_size = decrypted_last_block[-1]

        plain_buf_size = cipher_buf_size - padding_size

        plain_buf = bytearray(plain_buf_size)

        cur_cipher = 0
        cur_plain = 0

        while cur_plain < plain_buf_size:
            if cur_plain + self.AES_BLOCK_SIZE > plain_buf_size:
                break  # The last block already decrypted
            else:
                block = cipher_buf[cur_cipher:cur_cipher + self.AES_BLOCK_SIZE]
                decrypted_block = cipher.decrypt(block)
                plain_buf[cur_plain:cur_plain + self.AES_BLOCK_SIZE] = decrypted_block

                cur_plain += self.AES_BLOCK_SIZE
                cur_cipher += self.AES_BLOCK_SIZE

        # Fill the last fragment block
        if padding_size < self.AES_BLOCK_SIZE:
            plain_buf[cur_plain:] = decrypted_last_block[:-padding_size]

        return bytes(plain_buf)

def main():
    banner = r"""
                 ____                                     _       
     _ __  _   _|  _ \  ___  ___ ___  _ __   ___ _ __ ___| |_ ___ 
    | '_ \| | | | | | |/ _ \/ __/ _ \| '_ \ / __| '__/ _ \ __/ _ \
    | |_) | |_| | |_| |  __/ (_| (_) | | | | (__| | |  __/ ||  __/
    | .__/ \__, |____/ \___|\___\___/|_| |_|\___|_|  \___|\__\___|
    |_|    |___/                                                  
    """
    print(banner)

    parser = argparse.ArgumentParser(
        description='Extract secret key from a "pyconcrete" executable to decrypt bound .pye files.')
    parser.add_argument('pyconcrete', type=str, help='Path to the pyconcrete excecutable installed in your system path (ex: /usr/local/bin).')
    parser.add_argument('pye', type=str, help='Path to the encrypted .py file.')
    args = parser.parse_args()

    print('Analyzing file...')
    ea = ExecutableAnalyzer(args.pyconcrete)
    os, endian, arch, compiler = ea.analyze_file()
    print(f"[+] Executable Type: {os}, endian: {endian}, arch: {arch}, compiler: {compiler}\n")

    print('Extracting crypto keys from file...')
    disassembler = exe_disassembler(filepath=args.file, mode=arch)
    secret_key, secret_num = disassembler.get_secrets()

    if secret_key and secret_num:
        print('[*] Successfully extracted SECRET_KEY and SECRET_NUM!')

    print('Computing final key and decoding file...')
    deconcrete = PyDeconcrete(secret_key, secret_num)
    output_filepath = deconcrete.decrypt_file(args.pye)

    print(f'Successfully decrypted file!')
    print(f'Output file at: {output_filepath}')


if __name__ == "__main__":
    main()