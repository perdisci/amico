#!/usr/bin/python

# Copyright (c) 2009 Michael Still
# Released under the terms of the GNU GPL v2

# Mozilla publishes a rule file which may be used to calculate effective TLDs
# at:
#
#   http://mxr.mozilla.org/mozilla-central/source/netwerk/dns/src/
#   effective_tld_names.dat?raw=1
#
# Use that file to take a domain name and return a (domain, etld) tuple.
# Documentation for the rule file format is at:
#
#   https://wiki.mozilla.org/Gecko:Effective_TLD_Service

import re
import sys
import time

class etld(object):
  """Helper to determine the effective TLD portion of a domain name."""

  def __init__(self, datafile='effective_tld_names.dat'):
    """Load the data file ready for lookups."""

    self.rules = {}

    file = open(datafile)
    line = file.readline()
    while line:
      line = line.rstrip()
      if line and not line.startswith('//'):
        tld = line.split('.')[-1]
        self.rules.setdefault(tld, [])
        self.rules[tld].append(re.compile(self.regexpize(line)))

      line = file.readline()
    file.close()

  def regexpize(self, line):
    """Convert a rule to regexp syntax."""

    line = line[::-1].replace('.', '\\.').replace('*', '[^\\.]*').replace('!', '')
    return '^(%s)\.(.*)$' % line

  def parse(self, hostname):
    """Parse a hostanme into domain and etld portions."""

    hostname = hostname.lower()
    tld = hostname.split('.')[-1]
    hostname = hostname[::-1]
    domain = ''
    etld = ''

    for rule in self.rules[tld]:
      m = rule.match(hostname)
      if m and m.group(1) > etld:
        domain = m.group(2)[::-1]
        etld = m.group(1)[::-1]

    if not etld:
      raise Exception('Parse failed')

    return (domain, etld)


if __name__ == '__main__':
  e = etld()

  f = open(sys.argv[1])
  l = f.readline()
  start_time = time.time()

  while l:
    try:
      l = l.rstrip()
      print '%s -> %s' %(l, e.parse(l))
    except Exception, ex:
      print ex

    l = f.readline()
  
  print 'Took %f seconds' % (time.time() - start_time)
  f.close()
