##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

###
#
# A placeholder module for json_rpc_spec.rb
#
###
class MetasploitModule < Msf::Exploit::Remote
  include Msf::Exploit::Remote::DCERPC
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Placeholder scanner http title module',
        'Description' => 'Placeholder scanner http title module',
        'Author' => [],
        'License' => MSF_LICENSE
      )
    )
  end

  # No check method
  # def check
  #   # noop
  # end

  def run
    # noop
  end
end
