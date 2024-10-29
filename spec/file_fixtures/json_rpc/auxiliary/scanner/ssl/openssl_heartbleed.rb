##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

###
#
# A placeholder module for json_rpc_spec.rb
#
###
class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Placeholder openssl heartbleed module',
        'Description' => 'Placeholder openssl heartbleed module',
        'Author' => [],
        'License' => MSF_LICENSE
      )
    )
  end

  def check_host(_ip)
    # noop
  end

  def run_host(_ip)
    # noop
  end
end
