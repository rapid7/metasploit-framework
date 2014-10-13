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
      'Name'           => 'Poison Oracle TNS Listener',
      'Description'    => %q{
        This module simply checks the server for vulnerabilities like TNS Poison.
      },
      'Author'         => ['ir0njaw'],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => 'Oct 12 2014'))

    register_options(
      [
        Opt::RPORT(1521)
      ], self.class)

    deregister_options('RHOST')
  end

  def run_host(ip)
    begin
      connect

      pkt = tns_packet("(CONNECT_DATA=(COMMAND=service_register_NSGR))")
      sock.put(pkt)
      a= sock.read(100)
      	
      flag = a.include? "(ERROR_STACK=(ERROR="
	     if (flag==true) then print_error ip+" is not vulnerable"
	     else	print_good ip+" is vulnerable"
	     end

     	rescue ::Rex::ConnectionError, ::Errno::EPIPE
      print_error("#{ip} unable to connect to the server")
        
	
    rescue ::Rex::ConnectionError
    rescue ::Errno::EPIPE
	
    end
  end
end
