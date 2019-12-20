##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/cisco'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Cisco
  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Cisco Configuration Importer',
      'Description'   => %q{
        This module imports a Cisco IOS or NXOS device configuration.
        },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'h00die'],
    ))

    register_options(
      [
        OptPath.new('CONFIG', [true, 'Path to configuration to import']),
        Opt::RHOST(),
        Opt::RPORT(22)
      ])

  end

  def run
    unless ::File.exist?(datastore['CONFIG'])
      fail_with Failure::BadConfig, "Cisco config file #{datastore['CONFIG']} does not exists!"
    end
    cisco_config = ::File.open(datastore['CONFIG'], "rb")
    print_status('Importing config')
    cisco_ios_config_eater(datastore['RHOSTS'],datastore['RPORT'],cisco_config.read)
    print_good('Config import successful')
  end
end

