##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

##
# This module is based on, inspired by, or is a port of a plugin available in the Onapsis Bizploit Opensource ERP Penetration Testing framework - http://www.onapsis.com/research-free-solutions.php.
# Mariano Nuñez (the author of the Bizploit framework) helped me in my efforts in producing the Metasploit modules and was happy to share his knowledge and experience - a very cool guy. 
# I’d also like to thank Chris John Riley, Ian de Villiers and Joris van de Vis who have Beta tested the modules and provided excellent feedback. Some people just seem to enjoy hacking SAP :)
##

require 'msf/core'
require 'rubygems'
begin
  require 'nwrfc'
rescue LoadError
  abort("[x] This module requires the NW RFC SDK ruby wrapper (http://rubygems.org/gems/nwrfc) from Martin Ceronio.")
end

class Metasploit4 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include NWRFC

  def initialize
    super(
          'Name'        => 'SAP RFC Client Enumerator',
	      'Version'     => '$Revision:  $0.1',
	      'Description' => %q{
				               This module attempts to brute force the available SAP clients via the RFC interface. 
				               Default clients can be tested without needing to set a CLIENT.
                               This module can execute through a SAP Router if SRHOST and SRPORT values are set. 
                               The module requires the NW RFC SDK from SAP as well as the Ruby wrapper nwrfc (http://rubygems.org/gems/nwrfc).
				            },
          'References'  => [[ 'URL', 'http://labs.mwrinfosecurity.com' ]],
          'Author'      => [ 'nmonkee' ],
          'License'     => MSF_LICENSE
          )

  register_options(
		   [
             Opt::RPORT(3342),
		     OptString.new('CLIENT', [false, 'Client can be single (066), comma seperated list (000,001,066) or range (000-999)', '000,001,066']),
             OptString.new('SRHOST', [false, 'SAP Router Address', nil]),
             OptString.new('SRPORT', [false, 'SAP Router Port Number', nil]),
             OptBool.new('VERBOSE', [false, "Be Verbose", false])
           ], self.class)
  end

  def run_host(ip)
    user = "MWR"
    pass = "nmonkee"
    if datastore['CLIENT'].nil?
      print_status("Using default SAP client list")
      client = ['000', '001', '066']
    else
      if datastore['CLIENT'] =~ /^\d{3},/
        client = datastore['CLIENT'].split(/,/)
        print_status("Brute forcing clients #{datastore['CLIENT']}")
      elsif 
        datastore['CLIENT'] =~ /^\d{3}-\d{3}\z/
        array = datastore['CLIENT'].split(/-/)
        client = (array.at(0)..array.at(1)).to_a
        print_status("Brute forcing clients #{datastore['CLIENT']}")
      elsif
        datastore['CLIENT'] =~ /^\d{3}\z/
        client = datastore['CLIENT']
        print_status("Brute forcing client #{datastore['CLIENT']}")
      else  
        print_status("Invalid CLIENT - using default SAP client list instead")
        client = ['000', '001', '066']
      end
   end

   rport = datastore['rport'].to_s.split('')
   sysnr = rport[2]
   sysnr << rport[3]

   client.each { |client|
     enum_client(user,client,pass,datastore['rhost'],datastore['rport'],sysnr)
    }
 end

 def enum_client(user, client, pass, rhost, rport, sysnr)
  
  verbose = datastore['VERBOSE']
  print_status("#{rhost}:#{rport} [SAP] Trying client: '#{client}'") if verbose == true
  
  success = false
  
  ashost = rhost
  
  if datastore['SRHOST']
    if datastore['SRPORT']
      ashost = "H/#{datastore['SRHOST']}/S/#{datastore['SRPORT']}/H/#{rhost}/S/#{rport}"
    end
  end

  begin
    auth_hash = {"user" => user, "passwd" => pass, "client" => client, "ashost" => ashost, "sysnr" => sysnr}
    conn = Connection.new(auth_hash)		
    rescue NWError => e
      if e.message =~ /not available in this system/
        print_error("#{rhost}:#{rport} [SAP] client #{client} does not exist") if verbose == true
      else
        print_good("#{rhost}:#{rport} [SAP] client found - #{client}")
        success = true
      end
      return
    end
        
    if success
      print_good("#{rhost}:#{rport} [SAP] client found - #{client}")
      report_auth_info(
                     :host          => rhost,
                     :sname         => 'sap-gateway',
                     :proto         => 'tcp',
                     :port          => rport,
                     :client        => client,
                     :user          => user,
                     :pass          => pass,
                     :sysnr         => sysnr,
                     :source_type   => 'user_supplied',
                     :target_host   => rhost,
                     :target_port   => rport
                      )
      return
    end
  end
end
