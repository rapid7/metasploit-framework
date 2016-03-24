##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

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
        vulnearble. Otherwise, the target is vulnerable to malicious registrations.
      },
      'Author'         => ['ir0njaw (Nikita Kelesis) <nikita.elkey[at]gmail.com>'], # of Digital Security [http://dsec.ru]
      'References'     =>
        [
          [ 'URL', 'http://seclists.org/fulldisclosure/2012/Apr/204' ],
        ],
      'DisclosureDate' => 'Apr 18 2012',
      'License'        => MSF_LICENSE))

    register_options(
      [
        Opt::RPORT(1521)
      ], self.class)

    deregister_options('RHOST') # Provided by the TNS mixin, but not needed in a scanner module
  end

  def run_host(ip)
    begin
      connect
      send_packet = tns_packet("(CONNECT_DATA=(COMMAND=service_register_NSGR))")
      sock.put(send_packet)
      packet = sock.read(100)
      find_packet = /\(ERROR_STACK=\(ERROR=/ === packet
      find_packet == true ? print_error("#{ip}:#{rport} is not vulnerable ") : print_good("#{ip}:#{rport} is vulnerable")
      # TODO: Module should report_vuln if this finding is solid.
      rescue ::Rex::ConnectionError, ::Errno::EPIPE
      print_error("#{ip}:#{rport} unable to connect to the server")
    end
  end
end
