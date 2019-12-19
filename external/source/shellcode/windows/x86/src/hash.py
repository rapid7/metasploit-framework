#!/usr/bin/env python3
#=============================================================================#
# This script can detect hash collisions between exported API functions in
# multiple modules by either scanning a directory tree or just a single module.
# This script can also just output the correct hash value for any single API
# function for use with the 'api_call' function in 'block_api.asm'.
#
# Example: Detect fatal collisions against all modules in the C drive:
#     >hash.py /dir c:\
#
# Example: List the hashes for all exports from kernel32.dll (As found in 'c:\windows\system32\')
#     >hash.py /mod c:\windows\system32\ kernel32.dll
#
# Example: Simply print the correct hash value for the function kernel32.dll!WinExec
#     >hash.py kernel32.dll WinExec
#
# Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
#=============================================================================#
from sys import path
import os, time, sys

# Modify this path to pefile to suit your machine...
pefile_path = "D:\\Development\\Frameworks\\pefile\\"

path.append( pefile_path )
import pefile
#=============================================================================#
collisions = [  ( 0x006B8029, "ws2_32.dll!WSAStartup" ),
                ( 0xE0DF0FEA, "ws2_32.dll!WSASocketA" ),
                ( 0x6737DBC2, "ws2_32.dll!bind" ),
                ( 0xFF38E9B7, "ws2_32.dll!listen" ),
                ( 0xE13BEC74, "ws2_32.dll!accept" ),
                ( 0x614D6E75, "ws2_32.dll!closesocket" ),
                ( 0x6174A599, "ws2_32.dll!connect" ),
                ( 0x5FC8D902, "ws2_32.dll!recv" ),
                ( 0x5F38EBC2, "ws2_32.dll!send" ),

                ( 0x5BAE572D, "kernel32.dll!WriteFile" ),
                ( 0x4FDAF6DA, "kernel32.dll!CreateFileA" ),
                ( 0x13DD2ED7, "kernel32.dll!DeleteFileA" ),
                ( 0xE449F330, "kernel32.dll!GetTempPathA" ),
                ( 0x528796C6, "kernel32.dll!CloseHandle" ),
                ( 0x863FCC79, "kernel32.dll!CreateProcessA" ),
                ( 0xE553A458, "kernel32.dll!VirtualAlloc" ),
                ( 0x300F2F0B, "kernel32.dll!VirtualFree" ),
                ( 0x0726774C, "kernel32.dll!LoadLibraryA" ),
                ( 0x7802F749, "kernel32.dll!GetProcAddress" ),
                ( 0x601D8708, "kernel32.dll!WaitForSingleObject" ),
                ( 0x876F8B31, "kernel32.dll!WinExec" ),
                ( 0x9DBD95A6, "kernel32.dll!GetVersion" ),
                ( 0xEA320EFE, "kernel32.dll!SetUnhandledExceptionFilter" ),
                ( 0x56A2B5F0, "kernel32.dll!ExitProcess" ),
                ( 0x0A2A1DE0, "kernel32.dll!ExitThread" ),

                ( 0x6F721347, "ntdll.dll!RtlExitUserThread" ),

                ( 0x23E38427, "advapi32.dll!RevertToSelf" )
              ]

collisions_detected = {}
modules_scanned = 0
functions_scanned = 0
#=============================================================================#
def ror( dword, bits ):
  return ( dword >> bits | dword << ( 32 - bits ) ) & 0xFFFFFFFF
#=============================================================================#
def unicode( string, uppercase=True ):
  result = "";
  if uppercase:
    string = string.upper()
  for c in string:
    result += c + "\x00"
  return result
#=============================================================================#
def hash( module, function, bits=13, print_hash=True ):
  module_hash = 0
  function_hash = 0
  for c in unicode( module + "\x00" ):
    module_hash  = ror( module_hash, bits )
    module_hash += ord( c )
  for c in str( function + b"\x00" ):
    function_hash  = ror( function_hash, bits )
    function_hash += ord( c )
  h = module_hash + function_hash & 0xFFFFFFFF
  if print_hash:
    print("[+] 0x%08X = %s!%s" % ( h, module.lower(), function ))
  return h
#=============================================================================#
def scan( dll_path, dll_name, print_hashes=False, print_collisions=True ):
  global modules_scanned
  global functions_scanned
  #try:
  dll_name = dll_name.lower()
  modules_scanned += 1
  pe = pefile.PE( os.path.join( dll_path, dll_name ) )
  for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    if export.name is None:
      continue
    h = hash( dll_name, export.name, print_hash=print_hashes )
    for ( col_hash, col_name ) in collisions:
      if col_hash == h and col_name != "%s!%s" % (dll_name, export.name):
        if h not in collisions_detected.keys():
          collisions_detected[h] = []
        collisions_detected[h].append( (dll_path, dll_name, export.name) )
        break
    functions_scanned += 1
  #except:
  #  pass
#=============================================================================#
def scan_directory( dir ):
  for dot, dirs, files in os.walk( dir ):
    for file_name in files:
      if file_name[-4:] == ".dll":# or file_name[-4:] == ".exe":
        scan( dot, file_name )
  print("\n[+] Found %d Collisions.\n" % ( len(collisions_detected) ))
  for h in collisions_detected.keys():
    for (col_hash, col_name ) in collisions:
      if h == col_hash:
        detected_name = col_name
        break
    print("[!] Collision detected for 0x%08X (%s):" % ( h, detected_name ))
    for (collided_dll_path, collided_dll_name, collided_export_name) in collisions_detected[h]:
      print("\t%s!%s (%s)" % ( collided_dll_name, collided_export_name, collided_dll_path ))
  print("\n[+] Scanned %d exported functions via %d modules.\n" % ( functions_scanned, modules_scanned ))
#=============================================================================#
def usage():
    print("Usage: hash.py [/dir <path>] | [/mod <path> <module.dll>] | [<module.dll> <function>]")

def main( argv=None ):
  if not argv:
    argv = sys.argv
  if len( argv ) == 1:
    usage()
  else:
    print("[+] Ran on %s\n" % (  time.asctime( time.localtime() ) ))
    if argv[1] == "/dir":
      print("[+] Scanning directory '%s' for collisions..." % argv[2])
      scan_directory( argv[2] )
    elif argv[1] == "/mod":
      print("[+] Scanning module '%s' in directory '%s'..." % ( argv[3], argv[2] ))
      scan( argv[2], argv[3], print_hashes=True )
    elif len(argv) < 3:
      usage()
    else:
      hash( argv[1], argv[2] )
#=============================================================================#
if __name__ == "__main__":
  main()
#=============================================================================#
