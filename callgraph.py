# #!/usr/bin/env python3
# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

from collections import namedtuple
import argparse
import pickle
import os
import re
import subprocess
import sys
import tempfile

Function = namedtuple('Function', 'name location address code callees callers')

colorize = True
location = False

name_color = '\033[1;38;5;170m'
address_color = '\033[0;38;5;106m'
location_color = '\033[0;38;5;241m'
more_color = '\033[0;31m'
recur_color = '\033[0;31m'

colorize = lambda str, c: ('%s%s\033[0m' % (c, str))

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

def get_locations_table(elf):
    out = subprocess.check_output(['nm', '-l', '-C', elf], encoding='utf-8')
    symbols = re.findall('([0-9a-fA-F]{16,})\s+.\s+(\S+)\s+(\S+)\s*', out)

    if len(symbols) > 0:
        table = {}
        for sym in symbols:
            table[int(sym[0], 16)] = sym[2]
        return table
    
def get_functions(elf):
    # Disassemble elf binary using objdump
    args = ['objdump', '-C', '-d', elf]
    loc_table = None
    if location:
        loc_table = get_locations_table(elf)
        if not loc_table:
            args.insert(-1, '-l')

    out = subprocess.check_output(args, encoding='utf-8')

    # Each function ends with two new lines
    fcn_listings = out.split('\n\n')

    functions = FunctionTable()
    # Fetch function name
    header_re = re.compile('([0-9a-fA-F]{16,}) <(.+)>:')
    location_re = re.compile('.+\n\S+\(\):\n(\S+:\d+)')
    for listing in fcn_listings:
        m = header_re.match(listing)
        # Check if it is indeed a function
        if not m:
            continue

        address = int(m[1], 16)
        loc = []
        if location:
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
        functions.add(f)
    return functions

def analyze(table):
    # Consider both calls and jmps as calls.
    callstmt = re.compile('(callq|jmpq)\s+(\S+)\s+<(.+)>')
    leastmt = re.compile('(lea)\s+.+# (\S+)\s+<(.+)>\s*') 

    for fcn in table.functions():
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
                callee_fcn = table.lookup(callee_address)
                if callee_fcn not in fcn.callees:
                    fcn.callees.append(callee_fcn)
                if fcn not in callee_fcn.callers:
                    callee_fcn.callers.append(fcn)
            except:
                #print('Could not resolve callee %s %s' % (callee_address, callee_name))
                pass

def print_callstacks(table, fcnname, depth):
    def walk(stack, fcn, d, last=[]):
        desc = '%s %s' % (colorize(fcn.name, name_color), colorize(hex(fcn.address), address_color))
        if location and fcn.location:
            desc += ' %s' % colorize(fcn.location, location_color)
        prefix = ''
        for l in last[:-1]:
            prefix += ('\u2502   ' if not l else '    ')
        
        if len(stack) > 0:
            prefix = '  ' + prefix
            if last[-1]:
                prefix += '\u2514'
            else:
                prefix += '\u251c'                
            prefix += '\u2500\u2500'
            
        if len(stack) == depth and len(fcn.callers) > 0:
            desc += ' ' + colorize('...', more_color)
        if fcn in stack:
            desc += ' ' + colorize(' possible recursive call ', recursive_color)

        print('%s %s' % (prefix, desc))
        if len(stack) == depth or fcn in stack:
            return
        
        stack.append(fcn)                           
        if len(fcn.callers) == 0:
            pass
        else:
            for idx in range(0, len(fcn.callers)):
                caller = fcn.callers[idx]
                walk(stack, caller, d+1, last + [idx == len(fcn.callers)-1])
        stack.pop(-1)

    fcns = table.lookup_by_name(fcnname)
    if len(fcns) > 0:
        for fcn in fcns:
            walk([], fcn, 0)
    else:
        print('Function %s not found. Displaying possible matches.' % fcnname)
        for name in table.get_function_names():
            if fcnname in name:
                print_callstacks(table, name, depth)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Analyze enclave binary.')
    parser.add_argument('elf', help='path to enclave binary')
    parser.add_argument('function-name',  nargs='+',                        
                        help='function to print callstack for')
    parser.add_argument('-nc', '--no-color', metavar='', default=False,
                        action='store_const', const=True,
                        help='disable output colorization')
    parser.add_argument('-d', '--depth', metavar='', default=8, type=int,
                        help='maximum depth of callstack to print (default=8)')
    parser.add_argument('-nl', '--no-location', metavar='', default=False,
                        action='store_const', const=True)
    parser.add_argument('-c', '--cache', metavar='', default=False,
                        action='store_const', const=True,
                        help='cache processed data to speed up analysis')
    args = parser.parse_args()

    if args.no_color:
        colorize = lambda str, c: str

    location = not args.no_location
    table = None
    cache_used = False
    if args.cache:
        elfname_id = args.elf.replace('/', '_')
        cache_file = os.path.join(tempfile.gettempdir(), elfname_id + '.cache')
        #TODO: Check timestamps
        try:
            t1 = os.path.getmtime(args.elf)
            t2 = os.path.getmtime(cache_file)
            if t2 > t1:
                table = pickle.load(open(cache_file, 'rb'))
                cache_used = True
        except:
            pass
                        
    if not table:
        table = get_functions(args.elf)

    if args.cache and not cache_used:
        pickle.dump(table, open(cache_file, 'wb'))

    # Analyze
    analyze(table)
        
    names = args.__dict__['function-name']
    for name in names:
        print_callstacks(table, name, args.depth)
