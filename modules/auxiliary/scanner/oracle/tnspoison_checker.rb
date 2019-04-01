##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::TNS

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Oracle TNS Listener Checker',
      'Description'    => %q{
        This module checks the server for vulnerabilities like TNS Poison.
        Module sends a server a packet with command to register new TNS Listener and checks
        for a response indicating an error. If the registration is errored, the target is not
        vulnerable. Otherwise, the target is vulnerable to malicious registrations.
      },
      'Author'         => ['ir0njaw (Nikita Kelesis) <nikita.elkey[at]gmail.com>'], # of Digital Security [http://dsec.ru]
      'References'     =>
        [
          [ 'CVE', '2012-1675'],
          [ 'URL', 'https://seclists.org/fulldisclosure/2012/Apr/204' ],
        ],
      'DisclosureDate' => 'Apr 18 2012',
      'License'        => MSF_LICENSE))

    register_options(
      [
        Opt::RPORT(1521)
      ])
  end

  def run_host(ip)
    begin
      connect
      send_packet = tns_packet("(CONNECT_DATA=(COMMAND=service_register_NSGR))")
      sock.put(send_packet)
      packet = sock.read(100)
      if packet
        hex_packet = Rex::Text.to_hex(packet, ':')
        split_hex = hex_packet.split(':')
        find_packet = /\(ERROR_STACK=\(ERROR=/ === packet
        if find_packet == true #TNS Packet returned ERROR
          print_error("#{ip}:#{rport} is not vulnerable")
        elsif split_hex[5] == '02' #TNS Packet Type: ACCEPT
          print_good("#{ip}:#{rport} is vulnerable")
        elsif split_hex[5] == '04' #TNS Packet Type: REFUSE
          print_error("#{ip}:#{rport} is not vulnerable")
        else #All other TNS packet types or non-TNS packet type response cannot guarantee vulnerability
          print_error("#{ip}:#{rport} might not be vulnerable")
        end
      else
        print_error("#{ip}:#{rport} is not vulnerable")
      end
      # TODO: Module should report_vuln if this finding is solid.
      rescue ::Rex::ConnectionError, ::Errno::EPIPE
      print_error("#{ip}:#{rport} unable to connect to the server")
    end
  end
end
