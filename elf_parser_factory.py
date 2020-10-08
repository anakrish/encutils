import shutil
import sys
from objdump_parser import ObjDumpParser
from llvm_objdump_parser import LLVMObjDumpParser

def get_elf_parser(binary_file_name, show_symbol_files):
    if shutil.which("llvm-objdump") is not None:
            return LLVMObjDumpParser(binary_file_name, show_symbol_files)
    else:
        if sys.platform == "Win32":
            return None
        elif "linux" in sys.platform:
            return ObjDumpParser(binary_file_name, show_symbol_files)
    return None
        
