#!/usr/bin/env python3
#=============================================================================#
# A simple python build script to build the singles/stages/stagers and
# some usefull information such as offsets and a hex dump. The binary output
# will be placed in the bin directory. A hex string and usefull comments will
# be printed to screen.
#
# Example:
#     >python build.py stager_reverse_tcp_nx
#
# Example, to build everything:
#     >python build.py all > build_output.txt
#
# Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
#=============================================================================#
import os, sys, time
from subprocess import Popen
from struct import pack
#=============================================================================#
def clean( dir="./bin/" ):
  for root, dirs, files in os.walk( dir ):
    for name in files:
      if name != '.keep':
        os.remove( os.path.join( root, name ) )
#=============================================================================#
def locate( src_file, dir="./src/" ):
  for root, dirs, files in os.walk( dir ):
    for name in files:
      if src_file == name:
        return root
  return None

#=============================================================================#
def build( name ):
  location = locate( "%s.asm" % name )
  if location:
    input = os.path.normpath( os.path.join( location, name ) )
    output = os.path.normpath( os.path.join( "./bin/", name ) )
    p = Popen( ["nasm", "-f bin", "-O3", "-o %s.bin" % output, "%s.asm" % input ] )
    p.wait()
    xmit( name )
  else:
    print("[-] Unable to locate '%s.asm' in the src directory" % name)

#=============================================================================#
def xmit_dump_ruby( data, length=16 ):
  dump = ""
  for i in range( 0, len( data ), length ):
    bytes = data[ i : i+length ]
    hex = "\"%s\"" % ( ''.join( [ "\\x%02X" % x for x in bytes ] ) )
    if i+length <= len(data):
      hex += " +"
    dump += "%s\n" % ( hex )
  print(dump)

#=============================================================================#
def xmit_offset( data, name, value, match_offset=0 ):
  offset = data.find( value );
  if offset != -1:
    print("# %s Offset: %d" % ( name, offset + match_offset ))

#=============================================================================#
def xmit( name, dump_ruby=True ):
  bin = os.path.normpath( os.path.join( "./bin/", "%s.bin" % name ) )
  f = open( bin, 'rb')
  data = bytearray(f.read())
  print("# Name: %s\n# Length: %d bytes" % ( name, len( data ) ))
  xmit_offset( data, "Port", pack( ">H", 4444 ) )           # 4444
  xmit_offset( data, "LEPort", pack( "<H", 4444 ) )         # 4444
  xmit_offset( data, "Host", pack( ">L", 0x7F000001 ) )     # 127.0.0.1
  xmit_offset( data, "IPv6Host", pack( "<Q", 0xBBBBBBBBBBBBBBB1 ) ) # An IPv6 Address
  xmit_offset( data, "IPv6ScopeId", pack( "<L", 0xAAAAAAA1 ) ) # An IPv6 Scope ID
  xmit_offset( data, "HostName", b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\x00" )     # hostname filler
  xmit_offset( data, "RetryCounter", b"\x6a\x05", 1 )     # socket retry
  xmit_offset( data, "CodeLen", pack( "<L", 0x12345678 ) )  # Filler
  xmit_offset( data, "Hostname", b"https" )
  xmit_offset( data, "ExitFunk", pack( "<L", 0x0A2A1DE0 ) ) # kernel32.dll!ExitThread
  xmit_offset( data, "ExitFunk", pack( "<L", 0x56A2B5F0 ) ) # kernel32.dll!ExitProcess
  xmit_offset( data, "ExitFunk", pack( "<L", 0xEA320EFE ) ) # kernel32.dll!SetUnhandledExceptionFilter
  xmit_offset( data, "ExitFunk", pack( "<L", 0xE035F044 ) ) # kernel32.dll!Sleep
  xmit_offset( data, "EggTag1", pack( "<L", 0xDEADDEAD ) )  # Egg tag 1
  xmit_offset( data, "EggTag2", pack( "<L", 0xC0DEC0DE ) )  # Egg tag 2
  xmit_offset( data, "EggTagSize", pack( ">H", 0x1122 ) )   # Egg tag size
  xmit_offset( data, "RC4Key", b"RC4KeyMetasploit")          # RC4 key
  xmit_offset( data, "XORKey", b"XORK")                      # XOR key
  if( name.find( "egghunter" ) >= 0 ):
    null_count = data.count( "\x00" )
    if( null_count > 0 ):
      print("# Note: %d NULL bytes found." % ( null_count ))
  if dump_ruby:
    xmit_dump_ruby( data )

#=============================================================================#
def main( argv=None ):
  if not argv:
    argv = sys.argv
    if len( argv ) == 1:
        print("Usage: build.py [clean|all|<name>]")
    else:
        print("# Built on %s\n" % (  time.asctime( time.localtime() ) ))
        if argv[1] == "clean":
            clean()
        elif argv[1] == "all":
            for root, dirs, files in os.walk( "./src/egghunter/" ):
                for name in files:
                    build( name[:-4] )
            for root, dirs, files in os.walk( "./src/migrate/" ):
                for name in files:
                    build( name[:-4] )
            for root, dirs, files in os.walk( "./src/single/" ):
                for name in files:
                    build( name[:-4] )
            for root, dirs, files in os.walk( "./src/stage/" ):
                for name in files:
                    build( name[:-4] )
            for root, dirs, files in os.walk( "./src/stager/" ):
                for name in files:
                    build( name[:-4] )
            for root, dirs, files in os.walk( "./src/kernel/" ):
                for name in files:
                    build( name[:-4] )
        else:
            build( argv[1] )
#=============================================================================#
if __name__ == "__main__":
  main()
#=============================================================================#
