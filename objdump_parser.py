import subprocess
import re
import shutil
from utility import Function, FunctionTable, get_locations_table_through_nm

class ObjDumpParser():

    def __init__(self, binary_file_name, show_symbol_files):
        self.binary_file_name = binary_file_name
        self.show_symbol_files = show_symbol_files
        self.functions_table = FunctionTable()
        self.nm_available = False
        
        if shutil.which("nm") is not None:
            self.nm_available = True
            self.command_args = ['objdump', '-C', '-d', self.binary_file_name]
        else:
            self.command_args = ['objdump','-C', '-d', '-l', self.binary_file_name]
        
        self.functions_code_seperator               = "\n\n"
        self.functions_name_extractor_pattern       = '([0-9a-fA-F]{16,}) <(.+)>:'
        self.symbol_location_extraction_pattern     = '.+\n\S+\(\):\n(\S+:\d+)'
        self.calls_statement_matching_pattern       =  '(callq|jmpq)\s+(\S+)\s+<(.+)>'
        self.leas_statement_matching_pattern        = '(lea)\s+.+# (\S+)\s+<(.+)>\s*'

        self.construct_functions_table()
    
    def construct_functions_table(self):
        
        elf_ouput = subprocess.check_output(self.command_args, encoding='utf-8')
        fcn_listings = elf_ouput.split(self.functions_code_seperator)

        loc_table = None
        if self.show_symbol_files and self.nm_available:
            loc_table = get_locations_table_through_nm(self.binary_file_name)

        header_re   = re.compile(self.functions_name_extractor_pattern)
        location_re = re.compile(self.symbol_location_extraction_pattern)

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

    def analyze(self):
        # Consider both calls and jmps as calls.
        callstmt = re.compile(self.calls_statement_matching_pattern)
        leastmt = re.compile(self.leas_statement_matching_pattern) 

        for fcn in self.functions_table.functions():
            callees = callstmt.findall(fcn.code) + leastmt.findall(fcn.code)
            if len(callees) == 0:
                #print('%s %s calls []' % (hex(fcn.address), fcn.name))
                continue

            #print('%s %s calls' % (hex(fcn.address), fcn.name))
            for c in callees:
                # Avoid recursive calls.
                if c == fcn:
                    continue
                callee_address = int(c[1], 16)
                callee_name = c[2]
                #print('    %s %s' % (hex(callee_address), callee_name))
                try:
                    callee_fcn = self.functions_table.lookup(callee_address)
                    if callee_fcn not in fcn.callees:
                        fcn.callees.append(callee_fcn)
                    if fcn not in callee_fcn.callers:
                        callee_fcn.callers.append(fcn)
                except:
                    #print('Could not resolve callee %s %s' % (callee_address, callee_name))
                    pass
