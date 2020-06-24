#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
#=============================================================================#
# Example: Simply print the correct hash value for the function kernel32.dll!WinExec
#     >hash.py kernel32.dll WinExec
#
# Author: Ege Balcı (ege.balci[at]pm[dot]me)
#=============================================================================#
from sys import path
import os, time, sys, crcmod

def unicode( string, uppercase=True ):
  result = "";
  if uppercase:
    string = string.upper()+"\x00"
  for c in string:
    result += c + "\x00"
  return result
#=============================================================================#
def hash( module, function, bits=13, print_hash=True ):
  crc32_func = crcmod.mkCrcFun(0x11EDC6F41, initCrc=0, xorOut=0)
  h = crc32_func(unicode(module)+function+"\x00")
  print "[+] 0x%08X = %s!%s" % ( h, module.lower(), function )
  return h

#=============================================================================#
def main( argv=None ):
  if not argv:
    argv = sys.argv
  try:
    if len( argv ) == 1:
      print "Usage: crc32_hash.py [<module.dll> <function>]"
    else:
      print "[+] Ran on %s\n" % (  time.asctime( time.localtime() ) )
      hash( argv[1], argv[2] )
  except Exception, e:
    print "[-] ", e
#=============================================================================#
if __name__ == "__main__":
  main()
#=============================================================================#
