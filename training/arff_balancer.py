#! /usr/bin/python
###########################################################################
# Copyright (C) 2012 Babak Rahbarinia                                     #
# babak@cs.uga.edu                                                        #
#                                                                         #
# Distributed under the GNU Public License                                #
# http://www.gnu.org/licenses/gpl.txt                                     #   
#                                                                         #
# This program is free software; you can redistribute it and/or modify    #
# it under the terms of the GNU General Public License as published by    #
# the Free Software Foundation; either version 2 of the License, or       #
# (at your option) any later version.                                     #
#                                                                         #
###########################################################################

import argparse
import sys

parser = argparse.ArgumentParser(description='balances arff file based on requested classes')
parser.add_argument('-r', action='store', dest='input', help='input psql file', required=True)
parser.add_argument('-c', action='store', dest='classes', nargs='+', help='class names (space separated)')
parser.add_argument('-i', action='store', dest='intervals', nargs='+', type=int, help='balancing interval [-1 -> only test set, -2 -> remove] (space separated)')
parser.add_argument('-o', action='store', dest='reverse', nargs='+', help='inverse training and testing class names (space separated)')
parser.add_argument('-t', action='store_true', dest='gen_test', help='whether or not generate test set', default=False)
args = parser.parse_args()


def main():
    counters = dict()
    
    if args.classes != None or args.intervals != None:
        for i, c in enumerate(args.classes):
            counters[c] = [args.intervals[i], 0]
            
    reverse = []
    if args.reverse != None:
        for c in args.reverse:
            reverse.append(c)
    
    bf = open('%s.bal.arff' % args.input.split('.arff')[0], 'w')
    tf = None
    if args.gen_test:
        tf = open('%s.test.arff' % args.input.split('.arff')[0], 'w')
        
    with open(args.input) as in_file:
        for line in in_file:
            
            line = line.strip()
            
            if line.find('@') != -1 or line == '':
                if line.lower().startswith('@attribute class {'):
                    temp1 = '@ATTRIBUTE class {'
                    temp2 = []
                    for class_name in line.split('{')[1].rstrip('}').split(','):
                        class_name = class_name.strip()
                        if counters[class_name][0] != -2:
                            temp2.append(class_name)
                    temp1 += ','.join(temp2) + '}\n'
                    bf.write(temp1)
                    if tf != None:
                        tf.write(temp1)
                else:
                    bf.write('%s\n' % line)
                    if tf != None:
                        tf.write('%s\n' % line)

            else:
                current_class = line.split(',')[-1]
                
                # if class wasn't provided by the user, default interval = 1
                try:
                    counters[current_class][1] += 1
                except KeyError:
                    counters[current_class] = [1, 1]
                
                if counters[current_class][0] == -1:
                    tf.write('%s\n' % line)
                    continue
                if counters[current_class][0] == -2:
                    continue    
                    
                if counters[current_class][0] <= counters[current_class][1]:
                    if current_class not in reverse:
                        bf.write('%s\n' % line)
                    else:
                        tf.write('%s\n' % line)
                    counters[current_class][1] = 0
                else:
                    if tf != None:
                        if current_class not in reverse:
                            tf.write('%s\n' % line)
                        else:
                            bf.write('%s\n' % line)
    
    bf.close()
    if tf != None:
        tf.close()

if __name__ == '__main__':
    sys.exit(main())
