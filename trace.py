#!/usr/bin/env python3
# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

from collections import namedtuple
from queue import Queue

import argparse
import re
import subprocess
import sys
import threading


Object = namedtuple('Object', 'filename listing functions')
Function = namedtuple('Function', 'name qualifiedname object listing callee_names callees callers')

colorize = True


def process_object_listing(object):
    splits = re.split('\n[0-9a-fA-F]{16,} <(\S+)>:', object.listing)

    #    print(object.listing)
    # Note: Any ref is treated as a call.
    # It is worth exploring if we need to consider only callq, jmpq,
    # lea instructions.
    call_re = re.compile('R_X86_64_PLT32\s+(?:\.text\.)?(\w+)-')
    for i in range(1, len(splits), 2):
        name = splits[i]
        listing = splits[i+1]
        callee_names = call_re.findall(listing)
        fcn = Function(name=name,
                       qualifiedname='%s:%s'%(object.filename, name),
                       object=object,
                       listing=listing,
                       callee_names=callee_names,
                       callees=[],
                       callers=[])
        object.functions.append(fcn)

def process_load(filename, queue):
    print('Processing %s' % filename)
    listing = subprocess.check_output(['objdump', '-d', '-r', filename], encoding='utf-8')
    if filename.endswith('.o'):
        object = Object(filename=filename, listing=listing, functions=[])        
        process_object_listing(object)
        queue.put(object)
    elif filename.endswith('.a'):
        # Note: The \n at the start of the regex is needed for  fast matching.
        splits = re.split('\n(\S+)\.o:\s+file format \S+', listing)
        for i in range(1, len(splits), 2):
            object = Object(filename='%s(%s.o)' % (filename, splits[i]),
                            listing=splits[i+1],
                            functions=[])
            process_object_listing(object)
            queue.put(object)            

def process_loads(text):
    # Gather all loaded objects and libs
    loaded = re.findall('LOAD\s+(\S+)', text)
    threads = []
    queue = Queue()
    for l in loaded:
        t = threading.Thread(target=process_load, args=(l,queue))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

    object_table = {}
    while not queue.empty():
        obj = queue.get()
        object_table[obj.filename] = obj
    return object_table


def parse_cross_reference_table(text):
    split = re.split('Symbol\s+File', text)
    if len(split) != 2:
        print('Cross Reference Table not found')
        sys.exit(1)
    entries = re.split('\n(?!\s)', split[1])
    ignore = ['__GNU_EH_FRAME_HDR']
    cref_table = {}
    for entry in entries:
        split = str.split(entry)
        if len(split) < 2:
            continue
        name = split[0]
        if name in ignore:
            continue
        cref_table[name] = split[1:]
    return cref_table

def find_function(object, name):
    for fcn in object.functions:
        if fcn.name == name:
            return fcn

def append_unique(list, value):
    if value not in list:
        list.append(value)
                  
        
def link_functions(object_table, cref_table):
    unresolved = {}

    # Find list of objects based on cref table.
    # This limits objects to only those that have been processed by linker.
    objects = {}
    for refs in cref_table.values():
        for objname in refs:
            obj = object_table[objname]
            objects[objname] = obj

    # Link local calls
    for obj in objects.values():
        for fcn in obj.functions:
            for callee in fcn.callee_names:
                callee_fcn = find_function(obj, callee)
                if callee_fcn:
                    append_unique(fcn.callees, callee_fcn)
                    append_unique(callee_fcn.callers, fcn)
                    
    # Add functions based on cref table
    functions = {}
    for (name, refs) in cref_table.items():
        obj = objects[refs[0]]
        fcn = find_function(obj, name)
        if fcn:
            functions[name] = fcn
        else:
            functions[name] = Function(name=name,
                                       qualifiedname='undefined-%s' % callee,
                                       object=None,
                                       listing='',
                                       callee_names=[],
                                       callees=[],
                                       callers=[])
            
    # Link functions based on cref table
    for (name, refs) in cref_table.items():
        fcn = functions[name]
        match = False
        if name == 'oe_sgx_backtrace_symbols':
            print(refs)
            match = True
        for ref in refs:
            obj = objects[ref]
            #if fcn.object == obj:
            #    pass
            #else:
            for caller in obj.functions:
                if name in caller.callee_names:
                    if match:
                        print(caller.name)
                    append_unique(caller.callees, fcn)
                    append_unique(fcn.callers, caller)
        
    return (objects, functions)
                

def read_linker_map(filename):
    # Read contents of map file
    try:
        with open(filename, 'r') as f:
            text = f.read()
    except:
        print('Error reading %s' % filename)
        sys.exit(1)

    object_table = process_loads(text)
    cref_table = parse_cross_reference_table(text)
    return link_functions(object_table, cref_table)

def trace(objects, functions, fcnname, depth):
    def color_name(name):
        return '\x1b[0;1;38;5;136m%s\x1b[0m' % name if colorize else name
    def color_object(object):
        return '\x1b[0;2;38;5;117m%s\x1b[0m' % object if colorize else object
    def color_more(more):
        return '\x1b[0;1;48;5;52m%s\x1b[0m' % more if colorize else more
    def color_recursive(recur):
        return '\x1b[0;1;48;5;52m%s\x1b[0m' % recur if colorize else recur
    
    def walk(stack, fcn, d, last=[]):
        object_name = fcn.object.filename if fcn.object else ''
        desc = '%s %s' % (color_name(fcn.name), color_object(object_name))
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
            desc += ' ' + color_more('...')
        if fcn in stack:
            desc += ' ' + color_recursive(' possible recursive call ')

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

    if fcnname in functions:
        walk([], functions[fcnname], 0)
    else:
        found = False
        for obj in objects.values():
            fcn = find_function(obj, fcnname)
            if fcn:
                found = True
                walk([], fcn, 0)
                
        if not found:
            print('Function %s not found\n' % fcnname)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Trace symbol.')
    parser.add_argument('map-file', help='path to map file generated by linker')
    parser.add_argument('function-name',  nargs='+',                        
                        help='function to trace')
    parser.add_argument('-nc', '--no-color', metavar='', default=False,
                        action='store_const', const=True,
                        help='disable output colorization')
    parser.add_argument('-d', '--depth', metavar='', default=8, type=int,
                        help='maximum depth of callstack to print (default=8)')
    args = parser.parse_args()
    
    (objects, functions) = read_linker_map(args.__dict__['map-file'])

    print('\nTracing...')
    for fcnname in args.__dict__['function-name']:
        trace(objects, functions, fcnname, args.depth)

        
