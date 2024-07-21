import argparse
import pefile
from os.path import isfile

from exeDisassembler import exe_disassembler
from compilerEnum import *

def analyze_pe_file(file_path):
    pe = pefile.PE(file_path)
    is_windows_exe = True
    is_64bit = pe.FILE_HEADER.Machine in [pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64'],
                                          pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_IA64']]
    bit_architecture = 'x64' if is_64bit else 'x32'
    # PE files are always little-endian
    endian = "little"

    compiler = CompilerEnum.get_opinion(pe)

    return is_windows_exe, endian, bit_architecture, compiler


def analyze_file(file_path):
    if not isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    with open(file_path, 'rb') as f:
        magic = f.read(4)

    if magic.startswith(b'MZ'):
        return analyze_pe_file(file_path)
    elif magic.startswith(b'\x7fELF'):
        raise Exception('Linux ELF files are not supported yet!')
    else:
        raise ValueError("Unsupported file format")


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
    parser.add_argument('file', type=str, help='The path to the file to analyze')
    args = parser.parse_args()

    print('Analyzing file...')
    is_exe, endian, arch, compiler = analyze_file(args.file)
    print(f"[+] Executable Type: {'Windows' if is_exe else 'Linux'}, endian: {endian}, arch: {arch}, compiler: {compiler}\n")

    print('Extracting crypto keys from file...')
    disassembler = exe_disassembler(filepath=args.file, mode=arch)
    secret_key, secret_num = disassembler.get_secrets()

    if secret_key and secret_num:
        print('[*] Successfully extracted SECRET_KEY and SECRET_NUM!\n')


if __name__ == "__main__":
    main()
