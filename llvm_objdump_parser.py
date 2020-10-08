import subprocess
import re
import shutil
from utility import Function, FunctionTable, get_locations_table_through_nm

class LLVMObjDumpParser():
    def __init__(self, binary_file_name, show_symbol_files):
        self.binary_file_name = binary_file_name
        self.show_symbol_files = show_symbol_files
        self.nm_available = False
        self.symbol_to_address_dict= {}
        self.functions_table = FunctionTable()

        if shutil.which("nm") is not None:
            self.nm_available = True
            self.command_args = ['llvm-objdump', '-d',self.binary_file_name]
        else:
            self.command_args = ['llvm-objdump', '-d', '-l', self.binary_file_name]

        self.symbol_table_args = ['llvm-objdump', '-t', self.binary_file_name]
        self.functions_code_seperator            = "\n\n"
        self.functions_name_extractor_pattern    = '(^[\D\S]\S+):\n'
        self.address_extraction_pattern          = '([0-9a-fA-F]{16,})(.+).text\s+([0-9a-fA-F]+) (\S+)'
        self.symbol_location_extraction_pattern  = '(\S+):\n; (.+:\d+)\n'
        self.calls_statement_matching_pattern   =  '\s*([a-fA-F0-9]+):.+callq\s+(-*\d+)\s+<(.+)>'
        
        self.construct_symbols_to_address_dict()
        self.construct_functions_table()
        self.analyze()

    def construct_symbols_to_address_dict(self):
        symbols_output = subprocess.check_output(self.symbol_table_args, encoding='utf-8')
        symbols_output_lines = symbols_output.split("\n")
        symbols_extraction_matcher = re.compile(self.address_extraction_pattern)

        for line in symbols_output_lines:
            details = symbols_extraction_matcher.match(line)
            if details:
                address = int(details[1], 16)
                self.symbol_to_address_dict[details[4]] = address
        
        return

    def construct_functions_table(self):
        
        elf_output = subprocess.check_output(self.command_args, encoding='utf-8')
        elf_output = elf_output.replace("Disassembly of section .text:", "Disassembly of section .text:\n")
        fcn_listings = elf_output.split(self.functions_code_seperator)

        loc_table = None
        if self.show_symbol_files and self.nm_available:
            loc_table = get_locations_table_through_nm(self.binary_file_name)

        header_re   = re.compile(self.functions_name_extractor_pattern)
        location_re = re.compile(self.symbol_location_extraction_pattern)

        for listing in fcn_listings:
            details = header_re.match(listing)
            # Check if it is indeed a function
            if not details:
                continue
            
            function_name = details[1]
            address = self.symbol_to_address_dict[function_name]
            loc = []
            if self.show_symbol_files:
                if loc_table and address in loc_table:
                    loc = loc_table[address]
                else:
                    lm = location_re.match(listing)
                    if lm:
                        loc = lm[2]

            f = Function(name=function_name,
                        location=loc,
                        address=address, # Convert to hex for look up
                        code=listing,
                        callees=[],
                        callers=[])
            self.functions_table.add(f)
        return

    def analyze(self):
        # Consider both calls and jmps as calls.
        callstmt = re.compile(self.calls_statement_matching_pattern)

        for fcn in self.functions_table.functions():
            callstmt = re.compile(self.calls_statement_matching_pattern)
            callees = callstmt.findall(fcn.code)

            if len(callees) == 0:
                continue
            
            else:
                for callee in callees:
                    callee_address = int(callee[0], 16) + int(callee[1], 10) + 5
                    try:
                        callee_fcn = self.functions_table.lookup(callee_address)
                        if callee_fcn not in fcn.callees:
                            fcn.callees.append(callee_fcn)
                        if fcn not in callee_fcn.callers:
                            callee_fcn.callers.append(fcn)
                    except:
                        #print('Could not resolve callee %s %s' % (callee_address, callee_name))
                        pass