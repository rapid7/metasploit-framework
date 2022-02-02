##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Capture
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::DRDoS
  include Msf::Auxiliary::UDPScanner

  def initialize
    super(
      'Name'        => 'Chargen Probe Utility',
      'Description' => %q{
        Chargen is a debugging and measurement tool and a character
        generator service. A character generator service simply sends
        data without regard to the input.
        Chargen is susceptible to spoofing the source of transmissions
        as well as use in a reflection attack vector. The misuse of the
        testing features of the Chargen service may allow attackers to
        craft malicious network payloads and reflect them by spoofing
        the transmission source to effectively direct it to a target.
        This can result in traffic loops and service degradation with
        large amounts of network traffic.
      },
      'Author'      => 'Matteo Cantoni <goony[at]nothink.org>',
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          [ 'CVE', '1999-0103' ], # Note, does not actually trigger a flood.
          [ 'URL', 'http://tools.ietf.org/html/rfc864' ]
        ],
      'DisclosureDate' => 'Feb 08 1996')

      register_options([
        Opt::RPORT(19)
      ])
  end

  def run_host(rhost)
    data = Rex::Text.rand_text_alpha_lower(1)
    if spoofed?
      scanner_spoof_send(data, rhost, datastore['RPORT'], datastore['SRCIP'], datastore['NUM_REQUESTS'])
    else
      begin
        connect_udp
        udp_sock.write(data)
        r = udp_sock.recvfrom(65535, 0.1)

        if r and r[1]
          vprint_status("#{rhost}:#{rport} - Response: #{r[0].to_s}")
          res = r[0].to_s.strip
          if (res.match(/ABCDEFGHIJKLMNOPQRSTUVWXYZ/i) || res.match(/0123456789/))
            print_good("#{rhost}:#{rport} answers with #{res.length} bytes (headers + UDP payload)")
            report_service(:host => rhost, :port => rport, :proto => "udp", :name => "chargen", :info => res.length)
          end
        end
      rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused
        nil
      ensure
        disconnect_udp if self.udp_sock
      end
    end
  end
end
