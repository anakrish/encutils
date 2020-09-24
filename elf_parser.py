from collections import namedtuple
import subprocess
import re
import sys
import shutil

Function = namedtuple('Function', 'name location address code callees callers')

class FunctionTable:
    def __init__(self):
        self.table = {}
        self.table_by_name = {}
        
    def add(self, f):
        self.table[f.address] = f
        if f.name in self.table_by_name:
            self.table_by_name[f.name].append(f)
        else:
            self.table_by_name[f.name] = [f]
            
    def functions(self):
        return self.table.values()

    def lookup(self, address):
        return self.table[address]

    def lookup_by_name(self, name):
        try:
            return self.table_by_name[name]
        except:
            return []

    def get_function_names(self):
        return self.table_by_name.keys()

ParserConfigs = { "ObjDumpParser" : {
                    "parser_args_without_location":['objdump', '-C', '-d' ],
                    "parser_args_with_location":['objdump', '-C', '-d', '-l' ],
                    "functions_seperator":"\n\n",
                    "functions_heading_matching_matcher": re.compile('([0-9a-fA-F]{16,}) <(.+)>:'),
                    "symbol_location_matching_pattern": re.compile('.+\n\S+\(\):\n(\S+:\d+)'),
                    "calls_statement_matching_pattern": re.compile('(callq|jmpq)\s+(\S+)\s+<(.+)>'),
                    "LEA_statement_matching_pattern": re.compile('(lea)\s+.+# (\S+)\s+<(.+)>\s*')
                },
                "LLVMObjDumpParser" : {
                   
                }
            }

def get_locations_table_through_nm(binary_file_name):
    out = subprocess.check_output(['nm', '-l', '-C', binary_file_name], encoding='utf-8')
    symbols = re.findall('([0-9a-fA-F]{16,})\s+.\s+(\S+)\s+(\S+)\s*', out)

    if len(symbols) > 0:
        table = {}
        for sym in symbols:
            table[int(sym[0], 16)] = sym[2]
        return table

class ELFParser:

    def __init__(self, binary_file_name, show_symbol_files):
        self.binary_file_name = binary_file_name
        self.show_symbol_files = show_symbol_files
        self.nm_available = False
        self.functions_table = FunctionTable()
        if shutil.which("llvm-objdump") is not None:
            self.nm_available = True
        
        if shutil.which("llvm-objdump") is not None and False:
            self.parser_config = ParserConfigs["LLVMObjDumpParser"]
        else:
            if sys.platform == "Win32":
                self.parser_config = None
            elif "linux" in sys.platform:
                self.parser_config = ParserConfigs["ObjDumpParser"]
        self.construct_functions_table()
    
    def construct_functions_table(self):
        
        if self.nm_available:
            command_args = self.parser_config["parser_args_without_location"] + [self.binary_file_name]
        else:
            command_args = self.parser_config["parser_args_with_location"]+ [self.binary_file_name]
        elf_ouput = subprocess.check_output(command_args, encoding='utf-8')
        fcn_listings = elf_ouput.split(self.parser_config["functions_seperator"])

        loc_table = None
        if self.show_symbol_files and self.nm_available:
            loc_table = get_locations_table_through_nm(self.binary_file_name)

        header_re = self.parser_config["functions_heading_matching_matcher"]
        location_re = self.parser_config["symbol_location_matching_pattern"]

        for listing in fcn_listings:
            m = header_re.match(listing)
            # Check if it is indeed a function
            if not m:
                continue
            
            address = int(m[1], 16)
            loc = []
            if self.show_symbol_files:
                if loc_table and address in loc_table:
                    loc = loc_table[address]
                else:
                    lm = location_re.match(listing)
                    if lm:
                        loc = lm[1]

            f = Function(name=m[2],
                        location=loc,
                        address=int(m[1], 16), # Convert to hex for look up
                        code=listing,
                        callees=[],
                        callers=[])
            self.functions_table.add(f)
        return
