#!/usr/bin/env python3
# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


import argparse
import pickle
import tempfile
from elf_parser_factory import get_elf_parser
import os

colorize = True
location = False

name_color = '\033[1;38;5;170m'
address_color = '\033[0;38;5;106m'
location_color = '\033[0;38;5;241m'
more_color = '\033[0;31m'
recur_color = '\033[0;31m'
colorize = lambda str, c: ('%s%s\033[0m' % (c, str))
    

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
            desc += ' ' + colorize(' possible recursive call ', recur_color)

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

    elf_parser = get_elf_parser(args.elf, location) 
    if not table:
        table = elf_parser.functions_table
    else:
        elf_parser.functions_table = table

    if args.cache and not cache_used:
        pickle.dump(table, open(cache_file, 'wb'))

    elf_parser.analyze()
        
    names = args.__dict__['function-name']
    for name in names:
        print_callstacks(table, name, args.depth)
