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
import ConfigParser

parser = argparse.ArgumentParser(description='postgre sql to weka arff')
parser.add_argument('-r', action='store', dest='input', help='input psql file', required=True)
parser.add_argument('-w', action='store', dest='output', help='output file', required=True)
parser.add_argument('-c', action='store', dest='corrupt', help='corrupt column number (0-index)', type=int, required=True)
parser.add_argument('-t', action='store', dest='trusted_av_labels', help='trusted label column number (0-index)', type=int, required=True)
parser.add_argument('-vs', action='store', dest='vt_month_shelf', help='vt_month_shelf column number (0-index)', type=int, required=True)
parser.add_argument('-n', action='store', dest='num_av_label', help='av labels column number (0-index)', type=int, required=True)
args = parser.parse_args()

config = ConfigParser.RawConfigParser()
config.read('config.cfg')
malware_trusted_thresh = config.getint('classifier', 'malware_trusted_thresh')

# produces a label for each feature vector
def label_vector(corrupt, trusted_av, num_av, vt_month_shelf):
    
    # if no label is available
    if trusted_av == '?': trusted_av = -1
    else: trusted_av = int(trusted_av)
    if num_av == '?': num_av = -1
    else: num_av = int(num_av)
    
    # if dump is corrupt
    label = ''
    if corrupt == 't': label = 'corrupt_'
    
    # pos if there are trusted_av_labels
    if trusted_av >= malware_trusted_thresh: return label + 'pos'
    
    # neg if num_av_label = 0
    #if num_av == 0 and vt_month_shelf == 't': return label + 'neg'
    if num_av == 0: return label + 'neg'
    
    # all the other cases are unknown
    return label + 'unknown'
 

w = open(args.output, 'w')
w.write('@RELATION %s\n\n' % args.output.split('.')[0])

set_attributes = True
attribute_names = []
attribute_type = ''

with open(args.input, 'r') as in_file:
    for line in in_file:
        
        line = line.split('|')
        if len(line) < 2: continue
        line = map(str.strip, line)
        
        if set_attributes:
            
            if len(attribute_names) == 0:
                for attribute_name in line:
                    attribute_names.append(attribute_name)
            else:
                set_attributes = False
                
                for index, attribute in enumerate(line):
                    #if attribute.isdigit() or attribute == '': attribute_type = 'NUMERIC'
                    if attribute_names[index] == "extension_class":
                        attribute_type = "{common_ext,unknown_ext,common_fake,other_ext,no_url,no_ext}"
                    elif attribute_names[index] in ['sha1', 'dump_id', 'host', 'pattern1', 'pattern2', 'corrupt', 'vt_month_shelf']: 
                        attribute_type = 'STRING'
                    elif attribute == '':
                        attribute_type = 'NUMERIC'
                    else:
                        try:
                            ijk = float(attribute)
                        except ValueError, TypeError:
                            attribute_type = 'STRING'
                        else:
                            attribute_type = 'NUMERIC'
                    w.write('@ATTRIBUTE %d-%s %s\n' % (index+1, attribute_names[index], attribute_type))
                    
                w.write('@ATTRIBUTE class {pos, neg, unknown, corrupt_pos, corrupt_neg, corrupt_unknown}\n')    
                w.write('\n@DATA\n')
                
                for index, attribute in enumerate(line):
                    if attribute == '':
                        line[index] = '?'
                w.write('%s' % ','.join(line))
                w.write(',%s\n' % label_vector(line[args.corrupt], line[args.trusted_av_labels], line[args.num_av_label], line[args.vt_month_shelf]))        
            
        else:
            for index, attribute in enumerate(line):
                if attribute == '':
                    line[index] = '?'
            w.write('%s' % ','.join(line))
            w.write(',%s\n' % label_vector(line[args.corrupt], line[args.trusted_av_labels], line[args.num_av_label], line[args.vt_month_shelf]))
        
w.close()
