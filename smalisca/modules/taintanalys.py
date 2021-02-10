#!/usr/bin/python
# -*- coding: utf-8 -*-

#
# -----------------------------------------------------------------------------
#
# Copyright
# -----------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2015 Victor Dorneanu <info AAET dornea DOT nu>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

# note: substantial portion -> uses structure of modules/module_smali_parser.py

"""Implements taint analysis functionalities for Smali files"""

import codecs
import os
import re
from smalisca.core.smalisca_module import ModuleBase
from smalisca.core.smalisca_logging import log
import callextractor


class SmaliParser(ModuleBase):

    """Iterate through files and extract data

    Attributes:
        location (str): Path of dumped APK
        suffix (str): File name suffix
        current_path (str): Will be updated during parsing
        classes (list): Found classes

    """

    # flag to define if source api has been recently invoked without a corresponding move result
    # list of tainted registers
    # string of leaks

    src_invoked = False
    tainted = []
    leaks = []
    leak_sinks = []
    sinks = []
    sources = []

    def __init__(self, location, suffix):
        self.location = location
        self.suffix = suffix
        self.current_path = None
        self.classes = []

    def run(self):
        """Start main task"""

        self.parse_location()

    def parse_file(self, filename):
        """Parse specific file

        This will parse specified file for:
            * classes
            * class properties
            * class methods
            * calls between methods

        Args:
            filename (str): Filename of file to be parsed

        """

        with codecs.open(filename, 'r', encoding='utf8') as f:
            current_class = None
            current_method = None
            current_call_index = 0

            # Read line by line

            for l in f.readlines():

                if '.method' in l:
                    match_class_method = self.is_class_method(l)
                    if match_class_method:

                        # RESET TAINTED REGISTERS FOR EACH METHOD
                        # flag to define if source api has been recently invoked without a corresponding move result
                        
                        #print('tainted: ' + str(self.tainted) + '\n')

                        self.src_invoked = False

                        # list of tainted registers

                        self.tainted = []

                        # now continue for the following lines

                        continue

                if 'invoke' in l:
                    match_method_call = self.is_method_call(l)
                    if match_method_call:
                        m = self.extract_method_call(match_method_call)
                elif 'move-result-' in l:
                    match_move_result_kind = self.is_move_result_kind(l)
                    if match_move_result_kind:
                        m = self.extract_move_result_kind(match_move_result_kind)
                elif 'move-result' in l:
                    match_move_result = self.is_move_result(l)
                    if match_move_result:
                        m = self.extract_move_result(match_move_result)
                elif 'move-' in l:
                    match_move_kind = self.is_move_kind(l)
                    if match_move_kind:
                        m = self.extract_move_kind(match_move_kind)
                elif 'move' in l:
                    match_move = self.is_move(l)
                    if match_move:
                        m = self.extract_move(match_move)

        # Close fd

        f.close()

    def parse_location(self):
        """Parse files in specified location"""

        for (root, dirs, files) in os.walk(self.location):
            for f in files:
                if f.endswith(self.suffix):

                    file_path = root + '/' + f

                    # Set current path

                    self.current_path = file_path

                    # Parse file

                    log.debug('Parsing file:\t %s' % f)
                    self.parse_file(file_path)

    def is_class_method(self, line):
        match = re.search("\.method\s+(?P<method>.*)$", line)
        if match:
            log.debug('\t\tFound method: %s' % match.group('method'))
            return match.group('method')
        else:
            return None

    def is_method_call(self, line):
        match = re.search("invoke-\w+(?P<invoke>.*)", line)
        if match:
            log.debug('\t\t Found invoke: %s' % match.group('invoke'))
            return match.group('invoke')
        else:
            return None

    def is_move_result(self, line):
        match = re.search("move-result\w*(?P<moveresult>.*)", line)

        if match:
            log.debug('\t\t Found move-result: %s'
                      % match.group('moveresult'))
            return match.group('moveresult')
        else:
            return None
    
    def is_move_result_kind(self, line):
        match = re.search("move-result-\w+(?P<moveresultkind>.*)", line)

        if match:
            log.debug('\t\t Found move-result-kind: %s'
                      % match.group('moveresultkind'))
            return match.group('moveresultkind')
        else:
            return None

    def is_move(self, line):
        match = re.search("move\w*(?P<move>.*)", line)

        if match:
            log.debug('\t\t Found move: %s' % match.group('move'))
            return match.group('move')
        else:
            return None
    
    def is_move_kind(self, line):
        match = re.search("move-\w+(?P<movekind>.*)", line)

        if match:
            log.debug('\t\t Found move kind: %s' % match.group('movekind'))
            return match.group('movekind')
        else:
            return None

    def parse_args(self, arglist):
        res = []
        
        arglist = arglist.replace(' ','')

        if '{' in arglist:
            arglist = arglist[1:-1]
        
        if ',' in arglist:
            res = arglist.split(',')
        else:
            res.append(arglist)

        return res

    def extract_method_call(self, data):

        # Default values

        c_dst_class = data
        c_dst_method = None
        c_local_args = None
        c_dst_args = None
        c_ret = None

        # The call looks like this
        #  <destination class>) -> <method>(args)<return value>

        match = \
            re.search('(?P<local_args>\{.*\}),\s+(?P<dst_class>.*);->'
                      + '(?P<dst_method>.*)\((?P<dst_args>.*)\)(?P<return>.*)'
                      , data)

        if match:
            c_dst_class = match.group('dst_class')
            c_dst_method = match.group('dst_method')
            c_dst_args = match.group('dst_args')
            c_local_args = match.group('local_args')
            c_ret = match.group('return')

        c = {  # Destination class
               # Destination method
               # Local arguments
               # Destination arguments
               # Return value
            'to_class': c_dst_class,
            'to_method': c_dst_method,
            'local_args': c_local_args,
            'dst_args': c_dst_args,
            'return': c_ret,
            }

        invocation = ''
        tmp = str(c['to_class']) + ': ' \
            + callextractor.getArgs(str(c['return'])) + ' ' \
            + str(c['to_method']) + '(' \
            + callextractor.getArgs(str(c['dst_args'])) + ')'
        tmp = tmp.replace(': L', ': ')
        tmp = tmp.replace(';L', '; ')
        tmp = tmp.replace('/', '.')
        invocation = tmp[1:]

        # now check if source

        for line in open('SourcesAndSinks.txt'):
            line = line.rstrip()
            if invocation in line:
                if 'SOURCE' in line or 'BOTH' in line:

                    # if yes, global flag source = true

                    self.src_invoked = True
                    if invocation not in self.sources:
                        self.sources.append(invocation)

                # now check if sink

                if 'SINK' in line or 'BOTH' in line:

                    # if yes, check if local_args have any registers in the tainted list

                    if invocation not in self.sinks:
                        self.sinks.append(invocation)
                    for reg in self.parse_args(str(c['local_args'])):
                        if reg in self.tainted:

                            # if yes, then report leak
                            
                            s = '\ntainted register: ' + reg \
                                + ' in sink invocation: ' + invocation
                            
                            if s not in self.leaks:
                                self.leaks.append(s)
                            
                            if invocation not in self.leak_sinks:
                                self.leak_sinks.append(invocation)

        # during move-result, if source = true, then add register(s) to tainted list
        # after move-result, source = false (because immediate one is taken into account only)
        # in each move, check if src is in the tainted list
        # if yes, add dst to tainted list

        return c

    def extract_move_result(self, data):

        # Default values

        c_regs = None

        # The call looks like this
        #   move-result* <regs>
        
        #print('extract move result data: ' + str(data))

        match = re.search('(?P<regs>.*)', data)

        if match:
            c_regs = match.group('regs')

        c = {'regs': c_regs}
        
        #print(c)

        # during move-result, if source = true, then add register(s) to tainted list

        if self.src_invoked == True:
            self.tainted.extend(self.parse_args(str(c['regs']).strip()))

        # after move-result, source = false (because immediate one is taken into account only)

        self.src_invoked = False

        # in each move, check if src is in the tainted list
        # if yes, add dst to tainted list

        return c
    
    def extract_move_result_kind(self, data):

        # Default values

        c_regs = None

        # The call looks like this
        #   move-result-* <regs>
        
        #print('extract move result kind data: ' + str(data))

        match = re.search('(?P<regs>.*)', data)

        if match:
            c_regs = match.group('regs')

        c = {'regs': c_regs}
        
        #print(c)

        # during move-result, if source = true, then add register(s) to tainted list

        if self.src_invoked == True:
            self.tainted.extend(self.parse_args(str(c['regs']).strip()))

        # after move-result, source = false (because immediate one is taken into account only)

        self.src_invoked = False

        # in each move, check if src is in the tainted list
        # if yes, add dst to tainted list

        return c

    def extract_move(self, data):

        # Default values

        c_dst = None
        c_src = None

        # The call looks like this
        #   move* <dst>, <src>
        
        #print('extract move data: ' + str(data))

        match = re.search('(?P<dst>.*), (?P<src>.*)', data)

        if match:
            c_dst = match.group('dst')
            c_src = match.group('src')

        c = {'dst': c_dst, 'src': c_src}
        
        #print(c)
        
        # remove a register from the tainted list if it is overwritten
        if str(c['dst']).strip() in self.tainted:
            self.tainted.remove(str(c['dst']).strip())

        # in each move, check if src is in the tainted list

        if str(c['src']).strip() in self.tainted:

            # if yes, add dst to tainted list

            self.tainted.append(str(c['dst']).strip())

        return c
    
    def extract_move_kind(self, data):

        # Default values

        c_dst = None
        c_src = None

        # The call looks like this
        #   move-* <dst>, <src>
        
        #print('extract move-kind data: ' + str(data))

        match = re.search('(?P<dst>.*), (?P<src>.*)', data)

        if match:
            c_dst = match.group('dst')
            c_src = match.group('src')

        c = {'dst': c_dst, 'src': c_src}
        
        #print(c)
        
        # remove a register from the tainted list if it is overwritten
        if str(c['dst']).strip() in self.tainted:
            self.tainted.remove(str(c['dst']).strip())

        # in each move, check if src is in the tainted list

        if str(c['src']).strip() in self.tainted:

            # if yes, add dst to tainted list

            self.tainted.append(str(c['dst']).strip())

        return c

    def get_results(self):
        return self.leaks

    def get_sources(self):
        return self.sources

    def get_sinks(self):
        return self.sinks
    
    def get_leak_sinks(self):
        return self.leak_sinks
