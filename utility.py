from collections import namedtuple
import subprocess
import re

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


def get_locations_table_through_nm(binary_file_name):
    out = subprocess.check_output(['nm', '-l', binary_file_name], encoding='utf-8')
    symbols = re.findall('([0-9a-fA-F]{16,})\s+.\s+(\S+)\s+(\S+)\s*', out)

    if len(symbols) > 0:
        table = {}
        for sym in symbols:
            table[int(sym[0], 16)] = sym[2]
        return table