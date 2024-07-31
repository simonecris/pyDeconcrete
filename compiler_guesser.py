class BinaryReader:
    def __init__(self, pe):
        self.data = pe.__data__

    def read_int(self, offset):
        return int.from_bytes(self.data[offset:offset + 4], byteorder='little')


class CompilerEnum:

    def __init__(self, pe):
        self.pe = pe
        self.br = BinaryReader(pe)

    def get_opinion(self):
        offset_choice = "Unknown"

        dos_header = self.pe.DOS_HEADER
        nt_header = self.pe.NT_HEADERS

        # Check for Rust
        if self.is_rust():
            return "Rustc"

        # Check for Swift

        if self.is_swift():
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
            except FileNotFoundError:
                pass

        return offset_choice

    def is_rust(self):
        # Check for Rust specific indicators in the PE file
        rust_signature_1 = b"RUST_BACKTRACE"
        rust_signature_2 = b"/rustc/"
        try:
            for section in self.pe.sections:
                if section.Name.startswith(b'.rdata') and section.get_data():
                    rdata_section = section.get_data()
                    if rust_signature_1 in rdata_section:
                        return True
                    if rust_signature_2 in rdata_section:
                        return True
                    break
        except Exception:
            return False
        return False

    def is_swift(self):
        section_names = [section.Name.decode().strip('\x00') for section in self.pe.sections]
        # Check for Swift specific sections
        swift_sections = [".swift1", ".swift2", ".swift3"]
        return any(section in section_names for section in swift_sections)

