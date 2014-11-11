##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::TNS

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Oracle TNS Listener Checker',
      'Description'    => %q{
        This module checks the server for vulnerabilities like TNS Poison.
        Module sends to server a packet with command to register new TNS Listener and check response.
      },
      'Author'         => ['ir0njaw (Nikita Kelesis) <nikita.elkey@gmail.com>'], # of Digital Security [http://dsec.ru]
      'References'     =>
        [
          [ 'URL', 'http://seclists.org/fulldisclosure/2012/Apr/204' ],
        ],
      'License'        => MSF_LICENSE))

    register_options(
      [
        Opt::RPORT(1521)
      ], self.class)

    deregister_options('RHOST')
  end

  def run_host(ip)
    begin
      connect
      send_packet = tns_packet("(CONNECT_DATA=(COMMAND=service_register_NSGR))")
      sock.put(send_packet)
      packet = sock.read(100)
      find_packet = packet.include? "(ERROR_STACK=(ERROR="
      find_packet == true ? print_error("#{ip}:#{rport} is not vulnerable ") : print_good("#{ip}:#{rport} is vulnerable")
      rescue ::Rex::ConnectionError, ::Errno::EPIPE
      print_error("#{ip}:#{rport} unable to connect to the server")
    end
  end
end
