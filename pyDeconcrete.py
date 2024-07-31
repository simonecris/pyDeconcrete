import argparse
import logging
import pathlib

import pefile
from os.path import isfile

from compiler_guesser import CompilerEnum
from exeDisassembler import WindowsDisassembler

from Crypto.Cipher import AES

SECRET_KEY_LEN = 16  # The key is a md5 digest, so length is fixed at 16.
# https://github.com/Falldog/pyconcrete/blob/master/setup.py#L86


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
        self.key = bytes(key)

    def decrypt_file(self, pye_path):
        pye_path = pathlib.Path(pye_path)
        if not pye_path.exists():
            raise FileNotFoundError(f"File not found: {pye_path}")
        elif pye_path.suffix != '.pye':
            raise Exception(f'The provided file is not a .pye file!')

        pyc_path = pye_path.with_suffix('.pyc')
        if pyc_path.exists():
            raise Exception(f'Can\'t override existing file {pyc_path.absolute()}')

        with open(pye_path, 'rb') as pye:
            decrypted_pye = self.decrypt_buffer(pye.read())

        with open(pyc_path, 'wb') as pyc:
            pyc.write(decrypted_pye)

        return pyc_path.absolute()

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
        description='Extract secret key from a "pyconcrete" executable to decrypt associated .pye files.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('pyconcrete', type=str,
                        help='Path to the pyconcrete executable installed in your system path (ex: /usr/local/bin).')
    parser.add_argument('pye', type=str, help='Path to the encrypted .pye file.')
    parser.add_argument("-L", "--secret-key-len", type=int, help="Change default SECRET_KEY_LEN", default=16,
                        required=False)
    args = parser.parse_args()

    logger = logging.getLogger('pyDeconcrete')

    try:
        print('Analyzing file...')
        ea = ExecutableAnalyzer(args.pyconcrete)
        os, endian, arch, compiler = ea.analyze_file()
        print(f"[+] Executable Type: {os}, endian: {endian}, arch: {arch}, compiler: {compiler}\n")

        print('Extracting crypto keys from file...')
        disassembler = WindowsDisassembler(filepath=args.pyconcrete, mode=arch, secret_key_len=SECRET_KEY_LEN)
        secret_key, secret_num = disassembler.get_secrets()

        if secret_key and secret_num:
            print('[*] Successfully extracted SECRET_KEY and SECRET_NUM!\n')

        print('Computing final key and decoding file...')
        deconcrete = PyDeconcrete(secret_key, secret_num)
        print(f'[-] Decoded key: {deconcrete.key}')
        output_filepath = deconcrete.decrypt_file(args.pye)

        print(f'[*] Successfully decrypted file!')
        print(f'[+] Output file at: {output_filepath}')

        print('To get the .py source code, please use a decompiler like pycdc.')
    except Exception as err:
        logger.error(err)


if __name__ == "__main__":
    main()
