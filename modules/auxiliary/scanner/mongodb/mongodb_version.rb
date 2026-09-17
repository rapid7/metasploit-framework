##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'bson'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Mongodb
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'MongoDB Version Detector',
        'Description' => %q{
          This module connects to a MongoDB instance and retrieves the server version
          using the buildInfo command. Through MongoDB 8.0 this command requires no
          authentication; MongoDB 8.1+ requires authentication for buildInfo, so the
          module reports '8.1+' unless USERNAME is set, in which case it authenticates
          and retrieves the actual version string.

          Successfully tested against MongoDB 3.6.23, 4.4.30, 5.0.33, 6.0.28, 7.0.43, 8.3.11
          with and without authentication
        },
        'References' => [
          [ 'URL', 'https://docs.mongodb.com/manual/reference/command/buildInfo/' ]
        ],
        'Author' => [
          'h00die',
          'prithvee07'
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Reliability' => [],
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )
  end

  def run_host(_ip)
    connect

    version = get_version
    if version
      print_good("MongoDB version: #{version}")
    else
      print_warning('Unable to retrieve MongoDB version')
    end
  rescue StandardError => e
    print_error("Connection failed: #{e}")
  ensure
    disconnect
  end
end
