class CompilerEnum:
    Unknown = "Unknown"
    Rustc = "Rustc"
    Swift = "Swift"
    CLI = "CLI"
    GCC_VS = "GCC_VS"
    Clang = "Clang"
    VisualStudio = "VisualStudio"
    BorlandPascal = "BorlandPascal"
    BorlandCpp = "BorlandCpp"

    @staticmethod
    def get_opinion(pe):
        offset_choice = CompilerEnum.Unknown
        asm_choice = CompilerEnum.Unknown
        err_string_choice = CompilerEnum.Unknown

        dos_header = pe.DOS_HEADER
        nt_header = pe.NT_HEADERS

        # Check for Rust
        if CompilerEnum.is_rust(pe):
            return CompilerEnum.Rustc

        # Check for Swift
        section_names = [section.Name.decode().strip('\x00') for section in pe.sections]
        if CompilerEnum.is_swift(section_names):
            return CompilerEnum.Swift

        # Check for managed code (.NET)
        if nt_header.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress != 0:
            return CompilerEnum.CLI

        # Determine based on PE Header offset
        if dos_header.e_lfanew == 0x80:
            offset_choice = CompilerEnum.GCC_VS
        elif dos_header.e_lfanew == 0x78:
            offset_choice = CompilerEnum.Clang
        elif dos_header.e_lfanew >= 0x80:
            try:
                br = BinaryReader(pe)
                val1 = br.read_int(0x80)
                val2 = br.read_int(0x84)
                if val1 != 0 and val2 != 0 and (val1 ^ val2) == 0x536e6144:  # "DanS"
                    return CompilerEnum.VisualStudio
                if dos_header.e_lfanew == 0x100:
                    offset_choice = CompilerEnum.BorlandPascal
                elif dos_header.e_lfanew == 0x200:
                    offset_choice = CompilerEnum.BorlandCpp
                elif dos_header.e_lfanew > 0x300:
                    return CompilerEnum.Unknown
            except Exception as e:
                pass

        return offset_choice

    @staticmethod
    def is_rust(pe):
        # Check for Rust specific indicators in the PE file
        # This function needs to be implemented based on Rust-specific details
        return False

    @staticmethod
    def is_swift(section_names):
        # Check for Swift specific sections
        swift_sections = [".swift1", ".swift2", ".swift3"]
        return any(section in section_names for section in swift_sections)


class BinaryReader:
    def __init__(self, pe):
        self.pe = pe
        self.data = pe.__data__

    def read_int(self, offset):
        return int.from_bytes(self.data[offset:offset + 4], byteorder='little')